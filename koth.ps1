param(
    [string]$Mode  = 'status',   # status | submit
    [string]$File   = 'payload.js',
    [string]$Token  = '',
    [string]$Base   = ''
)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not $Base)  { $Base  = $env:KOTH_BASE }
if (-not $Base)  { $Base  = 'http://204.48.30.25:9000' }
if (-not $Token) { $Token = $env:KOTH_TOKEN }
if (-not $Token) { $Token = Read-Host 'DreamHack 토큰 입력' }
if (-not $Token) { Write-Host '토큰이 없습니다.'; exit 1 }

# 응답 본문을 UTF-8 로 디코드 (PS5.1 기본 Latin-1 → 한글 깨짐 방지)
function Get-Text($resp) {
    try   { return [Text.Encoding]::UTF8.GetString($resp.RawContentStream.ToArray()) }
    catch { return $resp.Content }
}
function Show-Submissions($sess) {
    $me  = Invoke-WebRequest -Uri ($Base + '/me/submissions') -WebSession $sess -UseBasicParsing -TimeoutSec 30
    $txt = Get-Text $me
    $j   = $txt | ConvertFrom-Json
    Write-Host ('활성(랭킹) 제출: #' + $j.active + '   총 ' + $j.total + ' / 최대 ' + $j.max_submissions)
    Write-Host ('{0,-4} {1,-10} {2,-7} {3,-8} {4}' -f 'id','status','best','rounds','reason')
    Write-Host ('-' * 60)
    foreach ($s in $j.submissions) {
        Write-Host ('{0,-4} {1,-10} {2,-7} {3,-8} {4}' -f `
            $s.id, $s.status, $(if($s.best -ne $null){$s.best}else{'-'}),
            $(if($s.scored_rounds -ne $null){$s.scored_rounds}else{'-'}),
            $(if($s.reason){$s.reason}else{''}))
    }
    return $j
}

Write-Host ('서버: ' + $Base)
Write-Host '로그인 중...'
try {
    $null = Invoke-WebRequest -Uri ($Base + '/login') -Method Post `
        -Body (@{ token = $Token } | ConvertTo-Json) -ContentType 'application/json' `
        -SessionVariable sess -UseBasicParsing -TimeoutSec 30
    Write-Host '로그인 OK'
} catch {
    Write-Host ('로그인/연결 실패: ' + $_.Exception.Message)
    exit 2
}

$watchId = $null
if ($Mode -eq 'submit') {
    if (-not (Test-Path $File)) { Write-Host ('페이로드 파일 없음: ' + $File); exit 1 }
    $data = [IO.File]::ReadAllText($File)
    $bytes = (Get-Item $File).Length
    Write-Host ('제출: ' + $File + ' (' + $bytes + ' bytes)')
    $bnd  = '----b' + [guid]::NewGuid().ToString('N')
    $LF   = "`r`n"
    $body = '--' + $bnd + $LF +
            'Content-Disposition: form-data; name="file"; filename="payload.js"' + $LF +
            'Content-Type: text/javascript' + $LF + $LF +
            $data + $LF +
            '--' + $bnd + '--' + $LF
    try {
        $sub = Invoke-WebRequest -Uri ($Base + '/submit') -Method Post -Body $body `
            -ContentType ('multipart/form-data; boundary=' + $bnd) `
            -WebSession $sess -UseBasicParsing -TimeoutSec 60
        $stxt = Get-Text $sub
        Write-Host ('SUBMIT ' + $sub.StatusCode + ' ' + $stxt)
        try { $watchId = ($stxt | ConvertFrom-Json).submission_id } catch {}
    } catch {
        Write-Host ('SUBMIT 실패: ' + $_.Exception.Message)
        if ($_.Exception.Response) {
            $rs = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())
            Write-Host $rs.ReadToEnd()
        }
    }
}

# 폴링: queued 가 사라질 때까지 (최대 ~2분). watchId 가 있으면 그 제출만 기준.
Write-Host ''
$deadline = (Get-Date).AddSeconds(120)
while ($true) {
    $j = Show-Submissions $sess
    $pending = @($j.submissions | Where-Object { $_.status -eq 'queued' -or $_.status -eq 'running' })
    if ($watchId -ne $null) {
        $target = $j.submissions | Where-Object { $_.id -eq $watchId }
        if ($target -and $target.status -ne 'queued' -and $target.status -ne 'running') {
            Write-Host ''
            Write-Host ('=> 제출 #' + $watchId + ' 결과: ' + $target.status +
                        '  best=' + $(if($target.best -ne $null){$target.best}else{'-'}) +
                        '  reason=' + $(if($target.reason){$target.reason}else{'(없음)'}))
            if ($target.status -eq 'ready' -and $target.best -ne $null) {
                Write-Host '   → 이 페이로드는 서버에서 정상 채점됨.'
            } elseif ($target.status -eq 'rejected') {
                Write-Host '   → 서버에서 에러로 거부됨 (이 node 버전에선 이 페이로드가 안 됨).'
            }
            break
        }
    } elseif ($pending.Count -eq 0) {
        break
    }
    if ((Get-Date) -gt $deadline) { Write-Host ''; Write-Host '(폴링 시간초과 — 잠시 후 다시 실행해 상태를 확인하세요)'; break }
    Write-Host '... 채점 대기, 5초 후 재조회 ...'
    Start-Sleep -Seconds 5
    Write-Host ''
}
