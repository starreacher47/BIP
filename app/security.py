import hashlib
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pyotp
from flask import current_app
from werkzeug.security import check_password_hash, generate_password_hash

TOKEN_NAMES={'token','access_token','auth_token','jwt','session','sessionid','session_id','sid','bearer','api_key','apikey'}
def hash_token(value): return hashlib.sha256(value.encode('utf-8',errors='ignore')).hexdigest()
def preview(value): return value[:6]+'…'+value[-4:] if len(value)>14 else '***'
def random_code(n=6): return ''.join(secrets.choice('0123456789') for _ in range(n))
def random_session(): return secrets.token_urlsafe(32)
def random_api_key(): return 'tsa_'+secrets.token_urlsafe(36)
def password_hash(v): return generate_password_hash(v,method='scrypt')
def password_ok(h,v): return check_password_hash(h,v)
def issue_jwt(user_id,minutes=15):
    now=datetime.now(timezone.utc); return jwt.encode({'sub':str(user_id),'iat':now,'exp':now+timedelta(minutes=minutes),'jti':secrets.token_hex(16)},current_app.config['SECRET_KEY'],algorithm='HS256')
def jwt_expiry(value):
    try:
        data = jwt.decode(
            value,
            options={
                "verify_signature": False,
                "verify_exp": False,
            },
        )
        exp = data.get("exp")

        if exp is None:
            return None

        return datetime.fromtimestamp(exp, timezone.utc).isoformat()

    except (
        jwt.PyJWTError,
        TypeError,
        ValueError,
        OverflowError,
    ):
        return None

def looks_like_token(name,value):
    if not value:return False
    n=(name or '').lower(); return n in TOKEN_NAMES or any(x in n for x in ('token','session','auth','jwt')) or (value.count('.')==2 and len(value)>30)
def new_otp_secret(): return pyotp.random_base32()
def verify_otp(secret,code): return bool(secret and code and pyotp.TOTP(secret).verify(code,valid_window=1))
def uuid7():
    ms=int(time.time()*1000); rand=secrets.randbits(74)
    value=(ms & ((1<<48)-1))<<80 | 0x7<<76 | ((rand>>62)&0xFFF)<<64 | 0x2<<62 | (rand & ((1<<62)-1))
    return str(uuid.UUID(int=value))
def seal_secret(value):
    # Educational at-rest obfuscation keyed by SECRET_KEY; production should use KMS/Vault/Fernet.
    key=hashlib.sha256(current_app.config['SECRET_KEY'].encode()).digest(); raw=value.encode(); enc=bytes(b^key[i%len(key)] for i,b in enumerate(raw)); return enc.hex()
def unseal_secret(value):
    key=hashlib.sha256(current_app.config['SECRET_KEY'].encode()).digest(); raw=bytes.fromhex(value); return bytes(b^key[i%len(key)] for i,b in enumerate(raw)).decode()
