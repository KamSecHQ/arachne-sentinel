import tempfile
from pathlib import Path

from arachne import storage
from arachne.waf.middleware import WAFMiddleware


def _tmp_db():
    tmp = Path(tempfile.mkdtemp()) / "test.db"
    storage.init_db(db_path=tmp)
    return tmp


def _make_environ(query_string="", method="GET", remote_addr="9.9.9.9"):
    return {
        "REQUEST_METHOD": method,
        "PATH_INFO": "/search",
        "QUERY_STRING": query_string,
        "REMOTE_ADDR": remote_addr,
        "wsgi.input": __import__("io").BytesIO(b""),
    }


def _dummy_app(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"ok"]


def test_benign_request_passes_through():
    db = _tmp_db()
    mw = WAFMiddleware(_dummy_app, db_path=db)
    environ = _make_environ(query_string="name=emirhan")
    captured = {}

    def start_response(status, headers):
        captured["status"] = status

    body = b"".join(mw(environ, start_response))
    assert captured["status"] == "200 OK"
    assert body == b"ok"


def test_malicious_request_is_blocked():
    db = _tmp_db()
    mw = WAFMiddleware(_dummy_app, db_path=db)
    environ = _make_environ(query_string="name=' OR '1'='1")
    captured = {}

    def start_response(status, headers):
        captured["status"] = status

    body = b"".join(mw(environ, start_response))
    assert captured["status"] == "403 Forbidden"
    assert b"403" in body

    events = storage.get_waf_events(db_path=db)
    assert len(events) == 1
    assert events[0]["blocked"] == 1


def test_rate_limit_blocks_after_threshold():
    db = _tmp_db()
    mw = WAFMiddleware(_dummy_app, db_path=db)
    statuses = []
    for _ in range(25):
        environ = _make_environ(query_string="", remote_addr="8.8.8.8")

        def start_response(status, headers):
            statuses.append(status)

        mw(environ, start_response)

    assert "403 Forbidden" in statuses
