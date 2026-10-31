#!/usr/bin/env python3
"""nodejail KotH 채점 서버에 payload.js 제출.

토큰은 커밋하지 않는다. 환경변수 KOTH_TOKEN 또는 첫 번째 인자로 넘긴다.

    KOTH_TOKEN=xxxx python submit.py            # payload.js 제출
    python submit.py <token> [payload.js]
"""
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.request as U
import uuid

BASE = os.environ.get("KOTH_BASE", "http://204.48.30.25:9000")


def main():
    token = os.environ.get("KOTH_TOKEN") or (sys.argv[1] if len(sys.argv) > 1 else "")
    if not token:
        sys.exit("토큰이 없다. KOTH_TOKEN 환경변수나 첫 인자로 넘겨라.")
    path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(__file__), "payload.js")
    data = open(path, "rb").read()
    if b"\x00" in data or not data:
        sys.exit("payload 가 비었거나 null byte 포함 -> 거부된다.")
    print(f"payload: {path} ({len(data)} bytes)")

    cj = http.cookiejar.CookieJar()
    op = U.build_opener(U.HTTPCookieProcessor(cj))

    def req(p, method="GET", obj=None, body=None, ctype=None):
        h = {"User-Agent": "koth-submit"}
        if obj is not None:
            body = json.dumps(obj).encode()
            h["Content-Type"] = "application/json"
        elif ctype:
            h["Content-Type"] = ctype
        try:
            x = op.open(U.Request(BASE + p, data=body, headers=h, method=method), timeout=30)
            return x.status, x.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    # dreamhack 로그인은 쿠키 세션을 요구한다 (x-team-token 헤더는 거부됨).
    s, _ = req("/login", "POST", {"token": token})
    if s != 200:
        sys.exit(f"로그인 실패: {s}")

    bnd = "----b" + uuid.uuid4().hex
    multipart = b"\r\n".join([
        ("--" + bnd).encode(),
        b'Content-Disposition: form-data; name="file"; filename="payload.js"',
        b"Content-Type: text/javascript",
        b"",
        data,
        ("--" + bnd + "--").encode(),
        b"",
    ])
    s, rb = req("/submit", "POST", body=multipart,
                ctype="multipart/form-data; boundary=" + bnd)  # 쿠키 세션만, 헤더 토큰 금지
    print("SUBMIT", s, rb.decode("utf-8", "replace"))

    s, rb = req("/me/submissions")
    print("SUBMISSIONS", rb.decode("utf-8", "replace"))


if __name__ == "__main__":
    main()
