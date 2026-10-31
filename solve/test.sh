#!/usr/bin/env bash
# 로컬 재현: vm2@3.11.5 를 깔고, payload 가 flag 를 정확히 출력하는지 확인.
# payload 는 /flag.txt 를 읽으므로, 로컬 테스트에서는 상대경로 flag.txt 로 치환해서 돌린다.
set -e
cd "$(dirname "$0")"
npm install --no-audit --no-fund
sed 's#/flag.txt#flag.txt#g' ../payload.js > /tmp/payload_local.js
echo -n "출력: "
node runner.js < /tmp/payload_local.js
echo
echo "기대: $(cat flag.txt)"
