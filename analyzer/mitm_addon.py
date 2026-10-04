"""mitmproxy addon.

Reverse-proxy mode:
    mitmdump -s mitm_addon.py --mode reverse:<TARGET_URL> ...

The client connects directly to mitmproxy.
"""

import os
from urllib.parse import parse_qs

import requests
from mitmproxy import ctx, http


class TokenAuditAddon:
    def load(self, loader):
        loader.add_option(
            "target_api",
            str,
            os.getenv("AUDITOR_CAPTURE_API_URL", ""),
            "Audit ingestion API",
        )
        loader.add_option(
            "ingest_key",
            str,
            os.getenv("MITMPROXY_CAPTURE_API_KEY", ""),
            "Ingestion API key",
        )
        loader.add_option(
            "auditor_ca",
            str,
            os.getenv("MITMPROXY_AUDITOR_CA", ""),
            "CA certificate used to verify the Auditor API",
        )

    def response(self, flow: http.HTTPFlow):
        req = flow.request
        res = flow.response

        body = {}
        ctype = req.headers.get("content-type", "")

        try:
            if "application/json" in ctype:
                body = req.json()
            elif "application/x-www-form-urlencoded" in ctype:
                body = parse_qs(req.get_text(strict=False))
        except Exception:
            body = {}

        payload = {
            "method": req.method,
            "url": req.pretty_url,
            "scheme": req.scheme,
            "host": req.host,
            "path": req.path.split("?")[0],
            "client_ip": (
                flow.client_conn.peername[0]
                if flow.client_conn.peername
                else None
            ),
            "user_agent": req.headers.get("user-agent"),
            "client_geo": req.headers.get("x-country"),
            "request_headers": dict(req.headers),
            "response_headers": dict(res.headers),
            "set_cookie_headers": res.headers.get_all("set-cookie"),
            "cookies": dict(req.cookies),
            "query_params": dict(req.query),
            "body_params": body,
            "status_code": res.status_code,
        }

        try:
            requests.post(
                ctx.options.target_api,
                json=payload,
                headers={
                    "X-API-Key": ctx.options.ingest_key,
                },
                timeout=3,
                verify=ctx.options.auditor_ca,
            )
        except Exception as exc:
            ctx.log.warn(f"Audit API unavailable: {exc}")


addons = [TokenAuditAddon()]