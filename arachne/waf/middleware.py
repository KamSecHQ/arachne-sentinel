"""
WAFMiddleware: herhangi bir WSGI uygulamasinin (Flask, vb.) onune konabilen
istek filtresi. Framework'e bagimli degildir - sadece WSGI standardina
uyar, bu yuzden istenirse baska bir Python web frameworku ile de kullanilabilir.

Kullanim:
    app = Flask(__name__)
    app.wsgi_app = WAFMiddleware(app.wsgi_app)
"""
import time
from collections import defaultdict, deque
from urllib.parse import unquote_plus

from .. import storage
from . import rules


class WAFMiddleware:
    def __init__(self, app, block_threshold=50, db_path=None):
        self.app = app
        self.block_threshold = block_threshold
        self.db_path = db_path
        # IP -> son istek zamanlarinin deque'si (rate limiting icin, bellek ici)
        self._recent_requests = defaultdict(deque)

    def _check_rate_limit(self, source_ip: str) -> bool:
        now = time.monotonic()
        window = self._recent_requests[source_ip]
        window.append(now)
        while window and now - window[0] > rules.RATE_LIMIT_WINDOW_SECONDS:
            window.popleft()
        return len(window) > rules.RATE_LIMIT_MAX_REQUESTS

    def _inspect(self, environ):
        source_ip = environ.get("REMOTE_ADDR", "unknown")
        method = environ.get("REQUEST_METHOD", "")
        path = environ.get("PATH_INFO", "")
        query_string = environ.get("QUERY_STRING", "")

        body = b""
        body_text = ""
        content_length = environ.get("CONTENT_LENGTH")
        if content_length:
            try:
                length = int(content_length)
                body = environ["wsgi.input"].read(length)
                # Downstream uygulamanin govdeyi tekrar okuyabilmesi icin geri koyuyoruz
                from io import BytesIO
                environ["wsgi.input"] = BytesIO(body)
                body_text = body.decode(errors="replace")
            except (ValueError, KeyError):
                pass

        score = 0
        reasons = []

        # QUERY_STRING ve form-encoded govde WSGI'de percent-encoded (URL
        # encoded) gelir (orn. tek tirnak "%27" olarak gorunur) - decode
        # etmeden taramak saldirilarin kacmasina yol acar, bu yuzden imza
        # taramasindan once mutlaka unquote ediyoruz.
        decoded_query = unquote_plus(query_string)
        decoded_body = unquote_plus(body_text)
        decoded_path = unquote_plus(path)

        for source_name, text in (("query", decoded_query), ("body", decoded_body),
                                   ("path", decoded_path)):
            for category, weight in rules.scan_text(text):
                score += weight
                reasons.append(f"{category} supesi ({source_name} icinde)")

        if self._check_rate_limit(source_ip):
            score += rules.RATE_LIMIT_WEIGHT
            reasons.append(
                f"Rate limit asildi: {rules.RATE_LIMIT_WINDOW_SECONDS}sn icinde "
                f"{rules.RATE_LIMIT_MAX_REQUESTS}'den fazla istek (olasi DDoS/asiri istek)"
            )

        blocked = score >= self.block_threshold

        storage.log_waf_event(source_ip, method, path, score, blocked, reasons,
                               db_path=self.db_path)

        return blocked, score, reasons

    def __call__(self, environ, start_response):
        blocked, score, reasons = self._inspect(environ)

        if blocked:
            body = (
                "<html><body><h1>403 Forbidden</h1>"
                "<p>Arachne Sentinel WAF bu istegi supheli buldu ve engelledi.</p>"
                "</body></html>"
            ).encode("utf-8")
            start_response("403 Forbidden", [
                ("Content-Type", "text/html; charset=utf-8"),
                ("Content-Length", str(len(body))),
                ("X-Arachne-WAF-Score", str(score)),
            ])
            return [body]

        return self.app(environ, start_response)
