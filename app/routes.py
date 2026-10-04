import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from io import BytesIO
from pathlib import Path

from flask import (
 Blueprint,
 abort,
 current_app,
 flash,
 jsonify,
 redirect,
 render_template,
 request,
 send_file,
 session,
 url_for,
)
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from werkzeug.utils import secure_filename

from . import csrf, limiter, oauth, socketio
from .audit import ingest_capture, register_attack_result
from .db import get_db
from .metrics import UPLOAD_BYTES
from .security import (
 hash_token,
 issue_jwt,
 new_otp_secret,
 password_hash,
 password_ok,
 random_api_key,
 random_code,
 random_session,
 seal_secret,
 verify_otp,
)
from .storage import finalize_upload

bp=Blueprint('main',__name__)
ALLOWED_UPLOAD_TYPES={'application/json','text/plain','text/csv','application/zip','application/octet-stream','application/x-httpd-php','image/png','image/jpeg'}

BASE_DIR = Path(__file__).resolve().parent
FONT_DIR = BASE_DIR / "fonts"

pdfmetrics.registerFont(
    TTFont("DejaVuSans", str(FONT_DIR / "DejaVuSans.ttf"))
)

pdfmetrics.registerFont(
    TTFont("DejaVuSans-Bold", str(FONT_DIR / "DejaVuSans-Bold.ttf"))
)

def login_required(fn):
 @wraps(fn)
 def w(*a,**k):
  if not session.get('user_id'):
   sid=request.cookies.get('APP_SESSION_ID'); row=get_db().execute("SELECT s.*,u.username,u.role,u.active FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.session_id=? AND s.active=1",(sid,)).fetchone() if sid else None
   if not row or not row['active']: return redirect(url_for('main.login'))
   try:
    if datetime.fromisoformat(row['expires_at'])<=datetime.now(timezone.utc): return redirect(url_for('main.login'))
   except ValueError:return redirect(url_for('main.login'))
   session.update(user_id=row['user_id'],username=row['username'],role=row['role'],app_sid=sid)
  return fn(*a,**k)
 return w

def role_required(*roles):
 def deco(fn):
  @wraps(fn)
  @login_required
  def w(*a,**k):
   if session.get('role') not in roles: abort(403)
   return fn(*a,**k)
  return w
 return deco

def api_auth(fn):
 @wraps(fn)
 def w(*a,**k):
  raw=request.headers.get('X-API-Key')
  if not raw and request.headers.get('Authorization','').lower().startswith('bearer '): raw=request.headers['Authorization'].split(None,1)[1]
  row=get_db().execute('SELECT * FROM api_keys WHERE key_hash=? AND active=1',(hash_token(raw or ''),)).fetchone()
  if not row:return jsonify(error='unauthorized'),401
  request.api_key=row
  get_db().execute('UPDATE api_keys SET last_used_at=CURRENT_TIMESTAMP WHERE id=?',(row['id'],)); get_db().commit()
  return fn(*a,**k)
 return w

def _create_session(user):
 db=get_db(); sid=random_session(); ttl=int(db.execute("SELECT value FROM settings WHERE key='session_ttl_minutes'").fetchone()[0]); exp=datetime.now(timezone.utc)+timedelta(minutes=ttl)
 db.execute('INSERT INTO sessions(user_id,session_id,ip,user_agent,expires_at,active,last_seen_at) VALUES(?,?,?,?,?,1,CURRENT_TIMESTAMP)',(user['id'],sid,request.remote_addr,request.user_agent.string,exp.isoformat())); db.commit()
 session.update(user_id=user['id'],username=user['username'],role=user['role'],app_sid=sid)
 resp=redirect(url_for('main.dashboard')); resp.set_cookie('APP_SESSION_ID',sid,secure=request.is_secure,httponly=True,samesite='Lax',max_age=ttl*60); return resp

@bp.route('/')
def index(): return render_template('index.html')

@bp.route('/register',methods=['GET','POST'])
def register():
 if request.method=='POST':
  db=get_db(); method=request.form['verification_method']; code=random_code() if method in ('email','phone') else request.form.get('invite_token','')
  if method=='token' and not secrets.compare_digest(code,current_app.config['INVITE_TOKEN']): flash('Неверный регистрационный токен','danger'); return render_template('register.html')
  try: db.execute('INSERT INTO users(username,password_hash,email,phone,verification_method,verification_code,verified) VALUES(?,?,?,?,?,?,?)',(request.form['username'],password_hash(request.form['password']),request.form.get('email'),request.form.get('phone'),method,code,1 if method=='token' else 0)); db.commit()
  except sqlite3.IntegrityError:
    flash('Имя пользователя уже занято', 'danger')
    return render_template('register.html')
  if method!='token': session['verify_user']=request.form['username']; flash(f'Демонстрационный OTP подтверждения: {code}','info'); return redirect(url_for('main.verify'))
  flash('Регистрация завершена','success'); return redirect(url_for('main.login'))
 return render_template('register.html')

@bp.route('/verify',methods=['GET','POST'])
def verify():
 if request.method=='POST':
  db=get_db(); u=db.execute('SELECT * FROM users WHERE username=?',(session.get('verify_user'),)).fetchone()
  if u and secrets.compare_digest(u['verification_code'] or '',request.form['code']): db.execute('UPDATE users SET verified=1,verification_code=NULL WHERE id=?',(u['id'],)); db.commit(); return redirect(url_for('main.login'))
  flash('Неверный код','danger')
 return render_template('verify.html')

@bp.route('/login',methods=['GET','POST'])
@limiter.limit('10 per minute')
def login():
 if request.method=='POST':
  u=get_db().execute('SELECT * FROM users WHERE username=?',(request.form['username'],)).fetchone()
  if not u or not u['active'] or not u['verified'] or not password_ok(u['password_hash'],request.form['password']): flash('Ошибка входа','danger'); return render_template('login.html')
  if u['otp_enabled']:
   session['pending_2fa_user']=u['id']; return redirect(url_for('main.login_otp'))
  return _create_session(u)
 return render_template('login.html')

@bp.route('/login/otp',methods=['GET','POST'])
@limiter.limit('10 per minute')
def login_otp():
 uid=session.get('pending_2fa_user'); u=get_db().execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone() if uid else None
 if not u:return redirect(url_for('main.login'))
 if request.method=='POST':
  if verify_otp(u['otp_secret'],request.form['otp']): session.pop('pending_2fa_user',None); return _create_session(u)
  flash('Неверный OTP','danger')
 return render_template('otp.html')

@bp.route('/oauth/<provider>')
def oauth_login(provider):
 if provider not in ('github','keycloak') or not hasattr(oauth,provider): abort(404)
 client=getattr(oauth,provider); return client.authorize_redirect(url_for('main.oauth_callback',provider=provider,_external=True))

@bp.route('/oauth/<provider>/callback')
def oauth_callback(provider):
 client=getattr(oauth,provider,None)
 if not client:abort(404)
 token=client.authorize_access_token(); info=token.get('userinfo')
 if provider=='github': info=client.get('user').json()
 subject=str(info.get('sub') or info.get('id')); username=(info.get('preferred_username') or info.get('login') or f'{provider}_{subject}')[:80]; email=info.get('email')
 db=get_db(); u=db.execute('SELECT * FROM users WHERE oauth_provider=? AND oauth_subject=?',(provider,subject)).fetchone()
 if not u:
  db.execute('INSERT INTO users(username,password_hash,email,verification_method,verified,oauth_provider,oauth_subject) VALUES(?,?,?,?,1,?,?)',(username,password_hash(secrets.token_urlsafe(32)),email,'oauth',provider,subject)); db.commit(); u=db.execute('SELECT * FROM users WHERE oauth_provider=? AND oauth_subject=?',(provider,subject)).fetchone()
 return _create_session(u)

@bp.route('/dashboard')
@login_required
def dashboard():
 db=get_db(); uploads=db.execute('SELECT * FROM uploads WHERE owner_user_id=? ORDER BY created_at DESC',(session['user_id'],)).fetchall(); sessions=db.execute('SELECT * FROM sessions WHERE user_id=? AND active=1 ORDER BY created_at DESC',(session['user_id'],)).fetchall(); return render_template('dashboard.html',jwt_token=issue_jwt(session['user_id']),uploads=uploads,sessions=sessions)

@bp.route('/profile/security',methods=['GET','POST'])
@login_required
def profile_security():
 db=get_db(); u=db.execute('SELECT * FROM users WHERE id=?',(session['user_id'],)).fetchone()
 if request.method=='POST':
  action=request.form['action']
  if action=='password':
   if not password_ok(u['password_hash'],request.form['old_password']): flash('Текущий пароль неверен','danger')
   else: db.execute('UPDATE users SET password_hash=? WHERE id=?',(password_hash(request.form['new_password']),u['id'])); db.commit(); flash('Пароль изменён','success')
  elif action=='otp_enable':
   secret=u['otp_secret'] or new_otp_secret(); db.execute('UPDATE users SET otp_secret=?,otp_enabled=1 WHERE id=?',(secret,u['id'])); db.commit(); flash(f'2FA включена. Секрет для приложения-аутентификатора: {secret}','success')
  elif action=='otp_disable': db.execute('UPDATE users SET otp_enabled=0 WHERE id=?',(u['id'],)); db.commit(); flash('2FA отключена','success')
  return redirect(url_for('main.profile_security'))
 return render_template('profile_security.html',user=u)

@bp.route('/profile/avatar',methods=['POST'])
@login_required
def avatar():
 f=request.files.get('avatar')
 if not f or f.mimetype not in {'image/png','image/jpeg'}: abort(415)
 name=f'avatar_{session["user_id"]}_{secrets.token_hex(4)}{Path(secure_filename(f.filename)).suffix}'; target=Path(current_app.config['UPLOAD_DIR'])/name; f.save(target)
 get_db().execute('UPDATE users SET avatar_path=? WHERE id=?',(name,session['user_id'])); get_db().commit(); return redirect(url_for('main.profile_security'))

@bp.route('/session/<int:sid>/revoke',methods=['POST'])
@login_required
def revoke_own_session(sid):
 get_db().execute('UPDATE sessions SET active=0 WHERE id=? AND user_id=?',(sid,session['user_id'])); get_db().commit(); return redirect(url_for('main.dashboard'))

@bp.route('/logout')
def logout():
 if session.get('app_sid'): get_db().execute('UPDATE sessions SET active=0 WHERE session_id=?',(session['app_sid'],)); get_db().commit()
 session.clear(); r=redirect(url_for('main.index')); r.delete_cookie('APP_SESSION_ID'); return r

@bp.route('/api/v1/audit/captures',methods=['POST'])
@csrf.exempt
@limiter.limit('10 per minute')
@api_auth
def captures_api(): return jsonify(id=ingest_capture(request.get_json(force=True),'rest-api')),201

@bp.route('/api/v1/audit/attack-results', methods=['POST'])
@csrf.exempt
@limiter.limit('10 per minute')
@api_auth
def attack_results_api():
    data = request.get_json(force=True) or {}

    attack_type = data.get('attack_type')
    target = data.get('target')
    success = bool(data.get('success'))
    details = data.get('details', '')

    if not attack_type or not target:
        return jsonify(error='attack_type and target are required'), 400

    rule_id = register_attack_result(
        attack_type=attack_type,
        target=target,
        success=success,
        details=details,
    )

    return jsonify(
        registered=bool(rule_id),
        rule_id=rule_id,
    ), 201

@bp.route('/api/v1/findings')
@csrf.exempt
@limiter.limit('10 per minute')
@api_auth
def findings_api(): return jsonify([dict(r) for r in get_db().execute('SELECT * FROM findings ORDER BY id DESC LIMIT 500')])

@bp.route('/api/v1/uploads',methods=['POST'])
@csrf.exempt
@limiter.limit('10 per minute')
@api_auth
def create_upload():
 data=request.get_json(force=True); upload_id=str(uuid.uuid4()); size=int(data.get('size',0)); ctype=data.get('content_type','application/octet-stream')
 if ctype not in ALLOWED_UPLOAD_TYPES: abort(415)
 get_db().execute('INSERT INTO uploads(id,owner_user_id,original_name,content_type,size_bytes) VALUES(?,?,?,?,?)',(upload_id,request.api_key['user_id'] or 1,secure_filename(data['filename']),ctype,size)); get_db().commit(); return jsonify(id=upload_id,chunk_size=current_app.config['UPLOAD_CHUNK_SIZE']),201

@bp.route('/api/v1/uploads/<upload_id>/chunks',methods=['PUT'])
@csrf.exempt
@limiter.limit('10 per minute')
@api_auth
def upload_chunk(upload_id):
 db=get_db(); row=db.execute('SELECT * FROM uploads WHERE id=?',(upload_id,)).fetchone()
 if not row:return jsonify(error='not_found'),404
 if request.content_type not in ('application/octet-stream',None):abort(415)
 part=Path(current_app.config['UPLOAD_DIR'])/(upload_id+'.part'); data=request.get_data(cache=False); part.parent.mkdir(parents=True,exist_ok=True)
 with part.open('ab') as out: out.write(data)
 received=part.stat().st_size; status='completed' if row['size_bytes'] and received>=row['size_bytes'] else 'uploading'; backend='local'; object_key=None
 if status=='completed': backend,object_key=finalize_upload(part,upload_id+'/'+row['original_name'])
 db.execute('UPDATE uploads SET received_bytes=?,status=?,stored_name=?,storage_backend=?,object_key=?,completed_at=CASE WHEN ?="completed" THEN CURRENT_TIMESTAMP ELSE completed_at END WHERE id=?',(received,status,part.name,backend,object_key,status,upload_id)); db.commit(); UPLOAD_BYTES.inc(len(data)); socketio.emit('upload_progress',{'id':upload_id,'received':received,'total':row['size_bytes'],'percent':round(received*100/max(row['size_bytes'],1),2)},room=upload_id); return jsonify(received=received,status=status,storage=backend)

@bp.route('/files/<upload_id>')
@login_required
def download_file(upload_id):
 row=get_db().execute('SELECT * FROM uploads WHERE id=?',(upload_id,)).fetchone()
 if not row or (row['owner_user_id']!=session['user_id'] and session.get('role') not in ('admin','superuser')):abort(403)
 return send_file(Path(current_app.config['UPLOAD_DIR'])/row['stored_name'],as_attachment=True,download_name=row['original_name'])

@bp.route('/files/<upload_id>/share',methods=['POST'])
@login_required
def share_file(upload_id):
 db=get_db(); row=db.execute('SELECT * FROM uploads WHERE id=? AND owner_user_id=?',(upload_id,session['user_id'])).fetchone()
 if not row:abort(403)
 raw=secrets.token_urlsafe(32); db.execute('INSERT INTO file_shares(upload_id,token_hash,expires_at,created_by) VALUES(?,?,?,?)',(upload_id,hash_token(raw),(datetime.now(timezone.utc)+timedelta(days=1)).isoformat(),session['user_id'])); db.commit(); flash('Ссылка: '+url_for('main.shared_file',token=raw,_external=True),'success'); return redirect(url_for('main.dashboard'))

@bp.route('/shared/<token>')
def shared_file(token):
 row=get_db().execute('SELECT u.* FROM file_shares s JOIN uploads u ON u.id=s.upload_id WHERE s.token_hash=? AND s.active=1',(hash_token(token),)).fetchone()
 if not row:abort(404)
 if row['expires_at'] and datetime.fromisoformat(row['expires_at'])<datetime.now(timezone.utc):abort(410)
 return send_file(Path(current_app.config['UPLOAD_DIR'])/row['stored_name'],as_attachment=True,download_name=row['original_name'])

@socketio.on('join_upload')
def join_upload(data):
 from flask_socketio import join_room
 join_room(data['id'])

@bp.route('/admin/login',methods=['GET','POST'])
@limiter.limit('10 per minute')
def admin_login():
 if request.method=='POST' and secrets.compare_digest(request.form['username'],current_app.config['ADMIN_USERNAME']) and secrets.compare_digest(request.form['password'],current_app.config['ADMIN_PASSWORD']):
  db=get_db(); u=db.execute("SELECT * FROM users WHERE role='superuser' LIMIT 1").fetchone()
  if not u: db.execute("INSERT INTO users(username,password_hash,verification_method,verified,role) VALUES(?,?, 'local',1,'superuser')",('superadmin',password_hash(secrets.token_urlsafe(32)))); db.commit(); u=db.execute("SELECT * FROM users WHERE role='superuser' LIMIT 1").fetchone()
  session.update(user_id=u['id'],username=u['username'],role='superuser'); return redirect(url_for('main.admin'))
 if request.method=='POST':flash('Неверные данные администратора','danger')
 return render_template('admin_login.html')

@bp.route('/admin',methods=['GET','POST'])
@role_required('admin','superuser')
def admin():
 db=get_db()
 if request.method=='POST':
  for key in ['token_in_url','token_over_http','cookie_secure','cookie_httponly','cookie_samesite','token_multi_client','expired_token_reuse','geo_change']: db.execute('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)',('rule.'+key,'1' if request.form.get(key) else '0'))
  db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('session_ttl_minutes',?)",(request.form.get('session_ttl_minutes','30'),)); db.commit(); flash('Настройки сохранены','success')
 settings={r['key']:r['value'] for r in db.execute('SELECT * FROM settings')}; stats={'captures':db.execute('SELECT count(*) FROM captures').fetchone()[0],'tokens':db.execute('SELECT count(*) FROM token_events').fetchone()[0],'findings':db.execute("SELECT count(*) FROM findings WHERE status='open'").fetchone()[0],'users':db.execute('SELECT count(*) FROM users').fetchone()[0]}
 return render_template('admin.html',settings=settings,stats=stats,findings=db.execute('SELECT * FROM findings ORDER BY id DESC LIMIT 100').fetchall(),users=db.execute('SELECT * FROM users ORDER BY id').fetchall(),api_keys=db.execute('SELECT * FROM api_keys ORDER BY id DESC').fetchall(),sessions=db.execute('SELECT s.*,u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.active=1 ORDER BY s.id DESC').fetchall())

@bp.route('/admin/audit/clear', methods=['POST'])
@role_required('superuser')
def clear_audit():
    db = get_db()

    db.execute('DELETE FROM findings')
    db.execute('DELETE FROM token_events')
    db.execute('DELETE FROM captures')
    db.execute('DELETE FROM attack_tests')

    db.commit()

    flash('Все записи аудита успешно удалены', 'success')

    return redirect(url_for('main.admin'))

@bp.route('/admin/users/<int:uid>',methods=['POST'])
@role_required('superuser')
def admin_user(uid):
 action=request.form['action']; db=get_db()
 if action=='role': db.execute('UPDATE users SET role=? WHERE id=?',(request.form['role'],uid))
 elif action=='toggle': db.execute('UPDATE users SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=?',(uid,))
 elif action=='revoke': db.execute('UPDATE sessions SET active=0 WHERE user_id=?',(uid,))
 db.commit(); return redirect(url_for('main.admin'))

@bp.route('/admin/api-keys', methods=['GET', 'POST'])
@role_required('admin', 'superuser')
def create_api_key():
    db = get_db()

    # Создание нового API-ключа
    if request.method == 'POST':
        name = request.form.get('name', '').strip()

        if not name:
            flash('Укажите название API-ключа', 'danger')
            return redirect(url_for('main.create_api_key'))

        user_id = request.form.get('user_id') or session['user_id']

        raw = random_api_key()

        db.execute(
            '''
            INSERT INTO api_keys(user_id, name, key_hash, key_prefix)
            VALUES (?, ?, ?, ?)
            ''',
            (
                user_id,
                name,
                hash_token(raw),
                raw[:12]
            )
        )

        db.commit()

        flash(
            'Новый API key. Скопируйте его сейчас — повторно он '
            'показываться не будет: ' + raw,
            'success'
        )

        return redirect(url_for('main.create_api_key'))

    # GET — показываем страницу управления API-ключами
    api_keys = db.execute(
        '''
        SELECT
            api_keys.*,
            users.username
        FROM api_keys
        LEFT JOIN users ON users.id = api_keys.user_id
        ORDER BY api_keys.id DESC
        '''
    ).fetchall()

    users = db.execute(
        '''
        SELECT id, username, role
        FROM users
        WHERE active = 1
        ORDER BY username
        '''
    ).fetchall()

    return render_template(
        'admin/api_keys.html',
        api_keys=api_keys,
        users=users
    )
@bp.route('/admin/external-tokens',methods=['GET', 'POST'])
@role_required('superuser')
def external_token():
 get_db().execute('INSERT INTO external_tokens(owner_user_id,name,provider,token_ciphertext) VALUES(?,?,?,?)',(session['user_id'],request.form['name'],request.form.get('provider'),seal_secret(request.form['token']))); get_db().commit(); flash('Токен внешнего API сохранён','success'); return redirect(url_for('main.admin'))

@bp.route('/admin/report.pdf')
@role_required('admin','superuser')
def report_pdf():
    from reportlab.pdfbase.pdfmetrics import stringWidth

    rows = get_db().execute(
        "SELECT * FROM findings "
        "ORDER BY CASE severity "
        "WHEN 'critical' THEN 1 "
        "WHEN 'high' THEN 2 "
        "WHEN 'medium' THEN 3 "
        "ELSE 4 END, id DESC"
    ).fetchall()

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)

    w, h = A4

    left = 40
    right = 40
    top = 50
    bottom = 50
    max_width = w - left - right

    def draw_wrapped(text, font_name="DejaVuSans", font_size=9, leading=13):
        nonlocal y

        c.setFont(font_name, font_size)

        text = str(text or "")
        current = ""

        for char in text:
            candidate = current + char

            if stringWidth(candidate, font_name, font_size) <= max_width:
                current = candidate
            else:
                if current:
                    if y < bottom:
                        c.showPage()
                        y = h - top
                        c.setFont(font_name, font_size)

                    c.drawString(left, y, current.rstrip())
                    y -= leading

                current = char

        if current:
            if y < bottom:
                c.showPage()
                y = h - top
                c.setFont(font_name, font_size)

            c.drawString(left, y, current.rstrip())
            y -= leading

    y = h - top

    draw_wrapped(
        "Token & Session Security Audit Report",
        "DejaVuSans-Bold",
        12,
        16,
    )

    y -= 12

    for r in rows:
        draw_wrapped(
            f"[{r['severity'].upper()}] {r['rule_id']} - {r['title']}",
            "DejaVuSans-Bold",
            9,
            13,
        )

        draw_wrapped(
            f"Category: {r['category']}",
            "DejaVuSans",
            9,
            13,
        )

        draw_wrapped(
            f"Evidence: {r['evidence'] or ''}",
            "DejaVuSans",
            9,
            13,
        )

        draw_wrapped(
            f"Recommendation: {r['recommendation'] or ''}",
            "DejaVuSans",
            9,
            13,
        )

        y -= 8

    c.save()
    buf.seek(0)

    return send_file(
        buf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="security_report.pdf",
    )

@bp.route('/health')
def health(): return jsonify(status='ok',version='2.0.0',database=get_db().execute('SELECT 1').fetchone()[0])

@limiter.request_filter
def health_exempt(): return request.path in ('/health','/metrics')

