import os

from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO
from flask_wtf.csrf import CSRFError, CSRFProtect
from prometheus_client import make_wsgi_app
from werkzeug.middleware.dispatcher import DispatcherMiddleware

from .db import init_db

csrf=CSRFProtect(); socketio=SocketIO(async_mode='threading',cors_allowed_origins=[]); oauth=OAuth()
limiter=Limiter(key_func=get_remote_address,default_limits=[])

from .audit import register_request_observer
from .middleware import register_security_middleware
from .routes import bp


def create_app(test_config=None):
    load_dotenv(); app=Flask(__name__,instance_relative_config=True)
    app.config.update(
      SECRET_KEY=os.getenv('SECRET_KEY','dev-only-change-me'), DATABASE=os.path.join(app.root_path,'..',os.getenv('DATABASE_PATH','instance/security.db')),
      AUDIT_SELF_TRAFFIC=os.getenv("AUDIT_SELF_TRAFFIC","true").lower() == "true",
      ADMIN_USERNAME=os.getenv('ADMIN_USERNAME','admin'), ADMIN_PASSWORD=os.getenv('ADMIN_PASSWORD','Admin123!'),
      INVITE_TOKEN=os.getenv('INVITE_TOKEN','DEMO-INVITE-2026'), ALLOWED_TEST_HOSTS=[x.strip() for x in os.getenv('ALLOWED_TEST_HOSTS','').split(',') if x.strip()],
      TRUSTED_ORIGINS=[x.strip() for x in os.getenv('TRUSTED_ORIGINS','').split(',') if x.strip()], MAX_CONTENT_LENGTH=int(os.getenv('MAX_CONTENT_LENGTH',str(2*1024**3))),
      UPLOAD_CHUNK_SIZE=int(os.getenv('UPLOAD_CHUNK_SIZE',str(8*1024**2))), UPLOAD_DIR=os.path.join(app.root_path,'..',os.getenv('UPLOAD_DIR','instance/uploads')),
      GITHUB_CLIENT_ID=os.getenv('GITHUB_CLIENT_ID'),GITHUB_CLIENT_SECRET=os.getenv('GITHUB_CLIENT_SECRET'),KEYCLOAK_CLIENT_ID=os.getenv('KEYCLOAK_CLIENT_ID'),KEYCLOAK_CLIENT_SECRET=os.getenv('KEYCLOAK_CLIENT_SECRET'),
      KEYCLOAK_SERVER_METADATA_URL=os.getenv('KEYCLOAK_SERVER_METADATA_URL'),ENABLE_MINIO=os.getenv('ENABLE_MINIO','false').lower()=='true',MINIO_ENDPOINT=os.getenv('MINIO_ENDPOINT','minio:9000'),MINIO_ACCESS_KEY=os.getenv('MINIO_ACCESS_KEY'),MINIO_SECRET_KEY=os.getenv('MINIO_SECRET_KEY'),MINIO_SECURE=os.getenv('MINIO_SECURE','false').lower()=='true',MINIO_BUCKET=os.getenv('MINIO_BUCKET','token-auditor')
    )
    if test_config: app.config.update(test_config)
    os.makedirs(os.path.dirname(os.path.abspath(app.config['DATABASE'])),exist_ok=True); os.makedirs(app.config['UPLOAD_DIR'],exist_ok=True)
    init_db(app); csrf.init_app(app);

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        app.logger.warning(
            "CSRF validation failed: %s",
            error.description,
        )
        return jsonify(
            error="csrf_error",
            message=error.description,
        ), 400

    limiter.init_app(app); oauth.init_app(app); socketio.init_app(app,cors_allowed_origins=app.config['TRUSTED_ORIGINS'])
    CORS(app,origins=app.config['TRUSTED_ORIGINS'],supports_credentials=True,resources={r'/api/*':{'origins':app.config['TRUSTED_ORIGINS']}})
    if app.config['GITHUB_CLIENT_ID']:
      oauth.register('github',client_id=app.config['GITHUB_CLIENT_ID'],client_secret=app.config['GITHUB_CLIENT_SECRET'],access_token_url='https://github.com/login/oauth/access_token',authorize_url='https://github.com/login/oauth/authorize',api_base_url='https://api.github.com/',client_kwargs={'scope':'user:email'})
    if app.config['KEYCLOAK_CLIENT_ID']:
      oauth.register('keycloak',client_id=app.config['KEYCLOAK_CLIENT_ID'],client_secret=app.config['KEYCLOAK_CLIENT_SECRET'],server_metadata_url=app.config['KEYCLOAK_SERVER_METADATA_URL'],client_kwargs={'scope':'openid email profile'})
    app.register_blueprint(bp)
    register_security_middleware(app)

    if app.config["AUDIT_SELF_TRAFFIC"]:
        register_request_observer(app)
    app.wsgi_app=DispatcherMiddleware(app.wsgi_app,{'/metrics':make_wsgi_app()})
    @app.errorhandler(413)
    def too_large(_): return (jsonify(error='payload_too_large',message='Файл превышает установленный лимит'),413) if request.path.startswith('/api/') else ('Файл слишком большой',413)
    @app.errorhandler(415)
    def unsupported(_): return jsonify(error='unsupported_media_type'),415
    @app.errorhandler(429)
    def rate_limit_error(_):
      from .metrics import RATE_LIMITED
      RATE_LIMITED.labels(request.path).inc()
      return jsonify(error='rate_limit_exceeded',message='Не более 10 запросов в минуту'),429
    return app
