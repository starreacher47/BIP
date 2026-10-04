import tempfile
from pathlib import Path

from app import create_app


def test_health_and_url_token():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "test.db"

        app = create_app({
            "TESTING": True,
            "DATABASE": str(db_path),
            "AUDIT_SELF_TRAFFIC": True,
        })

        c = app.test_client()

        assert c.get("/health").status_code == 200

        c.get("/?access_token=secret-demo-token")

        with app.app_context():
            from app.db import get_db

            count = get_db().execute(
                "SELECT count(*) FROM findings "
                "WHERE rule_id='TOKEN_IN_URL'"
            ).fetchone()[0]

            assert count >= 1