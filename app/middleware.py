import time
import uuid

from flask import current_app, g, request, session

from .db import get_db
from .metrics import HTTP_DURATION, HTTP_REQUESTS
from .security import uuid7


def register_security_middleware(app):
    @app.before_request
    def request_context():
        g.request_started = time.perf_counter()

        incoming = request.headers.get("X-Request-Id", "")
        g.request_id = incoming if _is_uuid7(incoming) else uuid7()

        origin = request.headers.get("Origin")

        if (
            origin
            and request.path.startswith("/api/")
            and origin not in current_app.config["TRUSTED_ORIGINS"]
        ):
            return {
                "error": "origin_not_allowed",
                "request_id": g.request_id,
            }, 403

    @app.after_request
    def headers(resp):
        duration = (
            time.perf_counter()
            - getattr(g, "request_started", time.perf_counter())
        ) * 1000

        request_id = getattr(g, "request_id", None)

        if not request_id:
            request_id = uuid7()
            g.request_id = request_id

        resp.headers["X-Request-Id"] = request_id

        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )

        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        resp.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )

        if request.is_secure:
            resp.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        db = get_db()
        db.execute(
            """
            INSERT INTO request_logs(
                request_id,
                user_id,
                method,
                path,
                status_code,
                remote_addr,
                duration_ms
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_id,
                session.get("user_id"),
                request.method,
                request.path,
                resp.status_code,
                request.headers.get(
                    "X-Forwarded-For",
                    request.remote_addr,
                ),
                duration,
            ),
        )
        db.commit()

        status_class = (
            f"{resp.status_code // 100}xx"
            if resp.status_code != 429
            else "429"
        )

        HTTP_REQUESTS.labels(
            request.method,
            request.path,
            status_class,
        ).inc()

        HTTP_DURATION.labels(
            request.method,
            request.path,
        ).observe(duration / 1000)

        return resp


def _is_uuid7(value):
    try:
        return uuid.UUID(value).version == 7
    except (ValueError, AttributeError):
        return False

