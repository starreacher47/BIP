import json
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

from flask import g, request

from .db import get_db
from .security import hash_token, jwt_expiry, looks_like_token, preview

SENSITIVE_NAMES={"password","passwd","secret","client_secret","otp","code","authorization","cookie","set-cookie"}
def sanitize_mapping(values):
    safe={}
    for name,val in (values or {}).items():
        low=str(name).lower()
        if low in SENSITIVE_NAMES or any(x in low for x in ("password","secret","token","session","auth","cookie","jwt","apikey","api_key")):
            if isinstance(val,list): safe[name]=[preview(str(x)) for x in val]
            else: safe[name]=preview(str(val))
        else: safe[name]=val
    return safe

RULES = {
    "TOKEN_IN_URL": (
        "high",
        "token_leakage",
        "Token transmitted in URL",
        "Transmit tokens using the Authorization header or a secure cookie."
    ),

    "TOKEN_OVER_HTTP": (
        "critical",
        "token_leakage",
        "Token transmitted over HTTP",
        "Use HTTPS for all authenticated traffic and enable HSTS."
    ),

    "COOKIE_NO_SECURE": (
        "high",
        "token_leakage",
        "Session cookie without Secure flag",
        "Set the Secure attribute on session cookies."
    ),

    "COOKIE_NO_HTTPONLY": (
        "high",
        "session_hijacking",
        "Session cookie without HttpOnly flag",
        "Set the HttpOnly attribute to prevent client-side JavaScript from reading the session cookie."
    ),

    "COOKIE_NO_SAMESITE": (
        "medium",
        "session_hijacking",
        "Session cookie without SameSite attribute",
        "Set SameSite=Lax or Strict; use SameSite=None only when Secure is also enabled."
    ),

    "TOKEN_MULTI_CLIENT": (
        "high",
        "session_hijacking",
        "Token used by multiple clients",
        "Revoke the token, bind the session to an appropriate client context, and require re-authentication when suspicious reuse is detected."
    ),

    "EXPIRED_TOKEN_REUSE": (
        "high",
        "session_hijacking",
        "Expired token reused",
        "Reject expired tokens and maintain a deny-list for revoked tokens when required."
    ),

    "GEO_CHANGE": (
        "high",
        "session_hijacking",
        "Sudden geographic change detected",
        "Require re-authentication and revoke the suspicious session when the change cannot be trusted."
    ),

    "SESSION_HIJACKING": (
        "critical",
        "session_hijacking",
        "Successful Session Hijacking detected",
        "Regenerate the Session ID after authentication and reject reuse of a compromised Session ID."
    ),

    "SESSION_FIXATION": (
        "critical",
        "session_fixation",
        "Successful Session Fixation detected",
        "Regenerate the Session ID after authentication and reject pre-set Session IDs."
    ),
}

def enabled(db, key):
    row=db.execute("SELECT value FROM settings WHERE key=?", ("rule."+key.lower(),)).fetchone()
    return row is None or row[0]=='1'

def add_finding(db, capture_id, rule_id, evidence):
    sev,cat,title,rec=RULES[rule_id]
    exists=db.execute("SELECT 1 FROM findings WHERE capture_id IS ? AND rule_id=? AND evidence=?",(capture_id,rule_id,evidence)).fetchone()
    if not exists:
        db.execute("INSERT INTO findings(capture_id,rule_id,severity,category,title,evidence,recommendation) VALUES(?,?,?,?,?,?,?)",(capture_id,rule_id,sev,cat,title,evidence,rec))

def register_attack_result(attack_type, target, success, details):
    db = get_db()

    if not success:
        return None

    rule_map = {
        "hijacking": "SESSION_HIJACKING",
        "fixation": "SESSION_FIXATION",
    }

    rule_id = rule_map.get(attack_type)
    if not rule_id:
        return None

    evidence = f"Target: {target}. {str(details or '').strip()}"

    exists = db.execute(
        """
        SELECT 1
        FROM findings
        WHERE capture_id IS NULL
          AND rule_id = ?
          AND evidence = ?
        """,
        (rule_id, evidence),
    ).fetchone()

    if not exists:
        add_finding(db, None, rule_id, evidence)

    db.commit()
    return rule_id

def ingest_capture(payload, source="api"):
    db=get_db(); url=payload.get("url",""); parsed=urlparse(url)
    headers=payload.get("request_headers") or {}; rheaders=payload.get("response_headers") or {}
    cookies=payload.get("cookies") or {}; query=payload.get("query_params") or parse_qs(parsed.query)
    body=payload.get("body_params") or {}
    cur=db.execute("""INSERT INTO captures(source,method,url,scheme,host,path,client_ip,user_agent,client_geo,request_headers,response_headers,cookies,query_params,body_params,status_code)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(source,payload.get('method'),url,payload.get('scheme') or parsed.scheme,payload.get('host') or parsed.hostname,payload.get('path') or parsed.path,payload.get('client_ip'),payload.get('user_agent') or headers.get('User-Agent'),payload.get('client_geo') or headers.get('X-Country'),json.dumps(sanitize_mapping(headers),ensure_ascii=False),json.dumps(sanitize_mapping(rheaders),ensure_ascii=False),json.dumps(sanitize_mapping(cookies),ensure_ascii=False),json.dumps(sanitize_mapping(query),ensure_ascii=False),json.dumps(sanitize_mapping(body),ensure_ascii=False),payload.get('status_code')))
    cid=cur.lastrowid
    token_items=[]
    auth=headers.get('Authorization') or headers.get('authorization')
    if auth:
        val=auth.split(None,1)[1] if ' ' in auth else auth; token_items.append(("Authorization",val,"header","access"))
    for loc, values in (("url",query),("body",body),("cookie",cookies)):
        for name,val in values.items():
            if isinstance(val,list): val=val[0] if val else ''
            if looks_like_token(name,str(val)): token_items.append((name,str(val),loc,"session" if 'sess' in name.lower() or name.lower() in {'sid','sessionid'} else 'access'))
    for name,val,loc,kind in token_items:
        th=hash_token(val); exp=jwt_expiry(val)
        db.execute("INSERT INTO token_events(capture_id,token_hash,token_preview,token_kind,location,name,client_ip,user_agent,client_geo,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)",(cid,th,preview(val),kind,loc,name,payload.get('client_ip'),payload.get('user_agent') or headers.get('User-Agent'),payload.get('client_geo') or headers.get('X-Country'),exp))
        if loc=='url' and enabled(db,'token_in_url'): add_finding(db,cid,'TOKEN_IN_URL',f"Parameter {name} found in {url}")
        if (payload.get('scheme') or parsed.scheme)=='http' and enabled(db,'token_over_http'): add_finding(db,cid,'TOKEN_OVER_HTTP',f"{name} transmitted over HTTP")
        prev=db.execute("SELECT DISTINCT client_ip,user_agent,client_geo FROM token_events WHERE token_hash=? AND id<>(SELECT max(id) FROM token_events)",(th,)).fetchall()
        if enabled(db,'token_multi_client') and any((p['client_ip'] and p['client_ip']!=payload.get('client_ip')) or (p['user_agent'] and p['user_agent']!=(payload.get('user_agent') or headers.get('User-Agent'))) for p in prev):
            add_finding(db,cid,'TOKEN_MULTI_CLIENT',f"Token {preview(val)} was observed from a different IP address or User-Agent")
        current_geo=payload.get('client_geo') or headers.get('X-Country')
        if current_geo and enabled(db,'geo_change') and any(p['client_geo'] and p['client_geo']!=current_geo for p in prev):
            add_finding(db,cid,'GEO_CHANGE',f"Token {preview(val)} changed geographic location to {current_geo}")
        if exp and enabled(db,'expired_token_reuse'):
            try:
                if datetime.fromisoformat(exp) < datetime.now(timezone.utc): add_finding(db,cid,'EXPIRED_TOKEN_REUSE',f"Expired JWT reused: {preview(val)}")
            except ValueError: pass
    
    set_cookie_headers = payload.get("set_cookie_headers") or []

    for set_cookie in set_cookie_headers:
        low = set_cookie.lower()
        sessionish = any(
            x in low for x in ("session", "sid", "token", "jwt")
        )

        if sessionish:
            if enabled(db, "cookie_secure") and "secure" not in low:
                add_finding(
                    db,
                    cid,
                    "COOKIE_NO_SECURE",
                    set_cookie,
                )

            if enabled(db, "cookie_httponly") and "httponly" not in low:
                add_finding(
                    db,
                    cid,
                    "COOKIE_NO_HTTPONLY",
                    set_cookie,
                )

            if enabled(db, "cookie_samesite") and "samesite=" not in low:
                add_finding(
                    db,
                    cid,
                    "COOKIE_NO_SAMESITE",
                    set_cookie,
                )
    
    db.commit(); return cid

def register_request_observer(app):
    @app.before_request
    def mark(): g._audit_started=True
    @app.after_request
    def observe(response):
        if request.path.startswith('/static/') or request.path=='/api/captures': return response
        try:
            body=request.form.to_dict(flat=False) if request.form else (request.get_json(silent=True) or {})
            payload={"method":request.method,"url":request.url,"scheme":request.scheme,"host":request.host.split(':')[0],"path":request.path,"client_ip":request.headers.get('X-Forwarded-For',request.remote_addr),"user_agent":request.user_agent.string,"client_geo":request.headers.get('X-Country'),"request_headers":dict(request.headers),"response_headers":dict(response.headers),"cookies":dict(request.cookies),"query_params":request.args.to_dict(flat=False),"body_params":body,"status_code":response.status_code}
            ingest_capture(payload,"flask")
        except Exception as exc: app.logger.warning("Audit observer error: %s",exc)
        return response
