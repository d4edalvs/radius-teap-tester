"""Refuse state-changing requests that another site's page sent.

The app has no login, so without this any page open in the same browser could
POST to it — start jobs that send RADIUS traffic, delete sessions, send CoA —
and binding to localhost would not help, because the browser is on localhost.

Browsers mark every cross-origin POST with an Origin header (and older ones at
least a Referer), which a page cannot forge. A request whose origin is not this
app's own is refused. A request with neither header did not come from a
browser page — curl, scripts, the test client — and is let through.

Behind a reverse proxy that rewrites Host, list the public origin in
TEAP_GUI_ALLOWED_ORIGINS (comma-separated, e.g. https://teap.lab.example).
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import PlainTextResponse

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _allowed_origins() -> set[str]:
    raw = os.environ.get("TEAP_GUI_ALLOWED_ORIGINS", "")
    return {o.strip().rstrip("/").lower() for o in raw.split(",") if o.strip()}


def is_same_origin(request: Request) -> bool:
    source = request.headers.get("origin") or request.headers.get("referer")
    if not source:
        return True
    if source == "null":                     # sandboxed frame, file://, etc.
        return False
    parts = urlsplit(source)
    if f"{parts.scheme}://{parts.netloc}".lower() in _allowed_origins():
        return True
    # X-Forwarded-Host cannot be set by a cross-origin page without a CORS
    # preflight, which this app never grants, so it is safe to accept here.
    own = {h.lower() for h in (request.headers.get("host"),
                               request.headers.get("x-forwarded-host")) if h}
    return parts.netloc.lower() in own


async def check_origin(request: Request, call_next):
    if request.method not in SAFE_METHODS and not is_same_origin(request):
        return PlainTextResponse(
            "Cross-origin request refused. If this app is behind a proxy, "
            "set TEAP_GUI_ALLOWED_ORIGINS to its public origin.",
            status_code=403)
    return await call_next(request)
