import os
from pathlib import Path

from app import create_app, socketio

app = create_app()

if __name__ == "__main__":
    host = os.getenv("AUDITOR_HOST")
    port = os.getenv("AUDITOR_PORT")

    if not host or not port:
        raise RuntimeError(
            "AUDITOR_HOST and AUDITOR_PORT must be configured in .env"
        )

    port = int(port)

    app_dir = Path(__file__).resolve().parent / "app"
    cert_file = app_dir / "cert" / "auditor.crt"
    key_file = app_dir / "cert" / "auditor.key"

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

    socketio.run(
        app,
        host=host,
        port=port,
        debug=True,
        allow_unsafe_werkzeug=True,
        ssl_context=ssl_context,
    )