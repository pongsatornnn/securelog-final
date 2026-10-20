


SECURITY_HEADERS = [
    (b"x-frame-options", b"DENY"),
    (b"content-security-policy", b"frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'"),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"same-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
]
_NAMES = {name for name, _ in SECURITY_HEADERS}


class SecurityHeadersMiddleware:


    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = [h for h in message.get("headers", []) if h[0].lower() not in _NAMES]
                message["headers"] = headers + SECURITY_HEADERS
            await send(message)

        await self.app(scope, receive, send_with_headers)
