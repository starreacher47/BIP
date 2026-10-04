import os
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import Flask, jsonify, make_response, request

load_dotenv()

app = Flask(__name__)


@app.get("/")
def index():
    return jsonify(
        service="target-app",
        message="Laboratory target application",
    )


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/safe")
def safe():
    return jsonify(
        status="ok",
        message="Safe endpoint",
    )


# ----------------------------------------------------------------------
# Intentionally vulnerable endpoints for laboratory testing
# ----------------------------------------------------------------------

@app.get("/unsafe/url-token")
def unsafe_url_token():
    token = request.args.get("token", "")

    return jsonify(
        message="Token received through URL",
        token=token,
    )


@app.get("/unsafe/cookie")
def unsafe_cookie():
    response = make_response(
        jsonify(
            message="Cookie without security flags",
        )
    )

    response.set_cookie(
        "LAB_SESSION_ID",
        "demo-session-token",
    )

    return response


@app.post("/unsafe/login")
def unsafe_login():
    response = make_response(
        jsonify(
            authenticated=True,
            message="Laboratory login",
        )
    )

    response.set_cookie(
        "LAB_SESSION_ID",
        "demo-session-token",
    )

    return response


# ----------------------------------------------------------------------
# Laboratory authentication endpoints
# ----------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return """
        <!doctype html>
        <html>
        <body>
            <form method="post" action="/login">
                <input type="hidden" name="csrf_token" value="lab-csrf-token">
                <input type="text" name="username">
                <input type="password" name="password">
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
        """

    response = make_response(
        jsonify(
            authenticated=True,
            message="Laboratory login successful",
        )
    )

    response.set_cookie(
        "LAB_SESSION_ID",
        "demo-session-token",
    )

    return response
    
@app.route("/unsafe/fixation-login", methods=["GET", "POST"])
def unsafe_fixation_login():
    if request.method == "GET":
        response = make_response("""
        <!doctype html>
        <html>
        <body>
            <form method="post" action="/unsafe/fixation-login">
                <input type="hidden" name="csrf_token" value="lab-csrf-token">
                <input type="text" name="username">
                <input type="password" name="password">
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
        """)

        # Если SID уже передан клиентом, оставляем его.
        # Иначе создаём лабораторный SID.
        session_id = request.cookies.get("LAB_SESSION_ID")

        if not session_id:
            session_id = "lab-fixed-session-id"

            response.set_cookie(
                "LAB_SESSION_ID",
                session_id
            )

        return response

    # УЯЗВИМАЯ ЛОГИКА:
    # после авторизации session ID НЕ меняется.
    session_id = request.cookies.get("LAB_SESSION_ID")

    if not session_id:
        session_id = "lab-fixed-session-id"

    response = make_response(
        jsonify(
            authenticated=True,
            message="Laboratory fixation login successful",
            session_id=session_id
        )
    )

    response.set_cookie(
        "LAB_SESSION_ID",
        session_id
    )

    return response


@app.get("/dashboard")
def dashboard():
    session_id = request.cookies.get("LAB_SESSION_ID")

    if not session_id:
        return jsonify(
            error="unauthorized",
        ), 401

    return jsonify(
        authenticated=True,
        session_id=session_id,
        message="Protected laboratory resource",
    )


@app.get("/logout")
def logout():
    response = make_response(
        jsonify(
            message="Logged out",
        )
    )

    response.delete_cookie("LAB_SESSION_ID")

    return response

@app.get("/unsafe/auth-header")
def unsafe_auth_header():
    authorization = request.headers.get("Authorization", "")

    return jsonify(
        message="Authorization header received",
        authorization=authorization,
    )

if __name__ == "__main__":
    from pathlib import Path

    target_url = os.getenv("TARGET_URL")

    if not target_url:
        raise RuntimeError("TARGET_URL is not configured in .env")

    parsed = urlparse(target_url)
    scheme = parsed.scheme.lower()

    if scheme not in {"http", "https"}:
        raise RuntimeError(
            f"TARGET_URL must use http:// or https://: {target_url}"
        )

    if not parsed.hostname:
        raise RuntimeError(f"Invalid TARGET_URL: {target_url}")

    ssl_context = None

    if scheme == "https":
        target_app_dir = Path(__file__).resolve().parent
        cert_file = target_app_dir / "cert" / "target.crt"
        key_file = target_app_dir / "cert" / "target.key"

        if not cert_file.is_file():
            raise RuntimeError(
                f"TLS certificate not found: {cert_file}"
            )

        if not key_file.is_file():
            raise RuntimeError(
                f"TLS private key not found: {key_file}"
            )

        ssl_context = (
            str(cert_file),
            str(key_file),
        )

    default_port = 443 if scheme == "https" else 80

    app.run(
        host=parsed.hostname,
        port=parsed.port or default_port,
        debug=os.getenv("FLASK_ENV", "development") == "development",
        ssl_context=ssl_context,
    )
