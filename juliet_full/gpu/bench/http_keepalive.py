"""Thread-local keep-alive HTTP client (stdlib). A fresh TCP connection from dell to 184-toast costs
~11 ms before the first byte (keep-alive requests: ~1.2 ms), so the probes reuse one connection per
thread, as the OpenAI SDK / httpx connection pools do."""
from __future__ import annotations

import http.client
import json
import threading
import urllib.parse

_local = threading.local()


def post_json(url: str, body: dict, timeout: float = 120) -> dict:
    parts = urllib.parse.urlsplit(url)
    key = (parts.hostname, parts.port)
    conns = _local.__dict__.setdefault("conns", {})
    for attempt in range(2):
        conn = conns.get(key)
        if conn is None:
            conn = conns[key] = http.client.HTTPConnection(parts.hostname, parts.port, timeout=timeout)
        try:
            conn.request("POST", parts.path, body=json.dumps(body), headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            data = resp.read()
        except (http.client.HTTPException, ConnectionError):
            conn.close()
            conns.pop(key, None)
            if attempt:
                raise
            continue
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status}: {data[:300]!r}")
        return json.loads(data)
    raise AssertionError("unreachable")
