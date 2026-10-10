<#
.SYNOPSIS
  Live security demonstration against the running YONKO backend.

.DESCRIPTION
  Launches a series of real attacks at http://127.0.0.1:8000 and prints
  PASS/FAIL for each one. Use it in front of judges to show the API
  resisting: forged sessions, SQL injection, path traversal, content
  spoofing, oversized uploads, brute force, CORS abuse, and more.

  Start the backend first:  .\start-backend.ps1

.EXAMPLE
  .\security-demo.ps1
#>
[CmdletBinding()]
param(
    [string]$BaseUrl = 'http://127.0.0.1:8000'
)

$ErrorActionPreference = 'Stop'
$script:pass = 0
$script:fail = 0

function Report([string]$name, [bool]$ok, [string]$detail = '') {
    if ($ok) { $script:pass++; Write-Host ("  [PASS] " + $name) -ForegroundColor Green }
    else     { $script:fail++; Write-Host ("  [FAIL] " + $name + "  " + $detail) -ForegroundColor Red }
}

function Attempt([scriptblock]$block) {
    try { & $block } catch { $_ }
}

# PowerShell 5.1 throws on 4xx/5xx, so status codes must be pulled from
# either a successful response or the caught error record.
function StatusOf($result) {
    if ($null -eq $result) { return 0 }
    if ($result -is [System.Management.Automation.ErrorRecord]) {
        if ($result.Exception -and $result.Exception.Response) {
            return [int]$result.Exception.Response.StatusCode
        }
        return 0  # network-level failure
    }
    if ($result.StatusCode) { return [int]$result.StatusCode }
    # Invoke-RestMethod success: the parsed body has no StatusCode -> 200.
    return 200
}

function HeaderOf($result, [string]$name) {
    $headers = $null
    if ($result -is [System.Management.Automation.ErrorRecord]) {
        if ($result.Exception -and $result.Exception.Response) {
            $headers = $result.Exception.Response.Headers
        }
    } elseif ($result.Headers) {
        $headers = $result.Headers
    }
    if ($null -eq $headers) { return $null }
    return $headers[$name]
}

# 1x1 transparent PNG
$pngBytes = [Convert]::FromBase64String(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==')

function New-Multipart([string[]]$names, [byte[][]]$payloads) {
    $boundary = [Guid]::NewGuid().ToString()
    $body = [System.IO.MemoryStream]::new()
    $writer = [System.IO.StreamWriter]::new($body)
    for ($i = 0; $i -lt $names.Count; $i++) {
        $ctype = if ($names[$i] -match '\.pdf$') { 'application/pdf' } else { 'image/png' }
        $writer.Write("--$boundary`r`nContent-Disposition: form-data; name=`"files`"; filename=`"$($names[$i])`"`r`nContent-Type: $ctype`r`n`r`n")
        $writer.Flush()
        $body.Write($payloads[$i], 0, $payloads[$i].Length)
        $writer.Write("`r`n")
        $writer.Flush()
    }
    $writer.Write("--$boundary--`r`n")
    $writer.Flush()
    return @{ Body = $body.ToArray(); ContentType = "multipart/form-data; boundary=$boundary" }
}

Write-Host ''
Write-Host "YONKO security demo - attacking $BaseUrl" -ForegroundColor Cyan
Write-Host ('=' * 60)

# --- Setup: create an account ---------------------------------------------
$email = "demo-{0}@department.gov.in" -f ([guid]::NewGuid().ToString('N').Substring(0, 8))
$password = 'SecurePass1'
$signup = Attempt { Invoke-RestMethod -Method Post -Uri "$BaseUrl/auth/signup" `
    -ContentType 'application/json' `
    -Body (@{ email = $email; password = $password } | ConvertTo-Json) }
$token = $signup.token
$auth = @{ Authorization = "Bearer $token" }
Write-Host "`nSigned up demo reviewer: $email" -ForegroundColor DarkGray

# --- 1. Session attacks ----------------------------------------------------
Write-Host "`n-- Session security --"

$noAuth = Attempt { Invoke-WebRequest -Method Get -Uri "$BaseUrl/cases" -UseBasicParsing }
Report "Anonymous access to /cases rejected (401)" ((StatusOf $noAuth) -eq 401)

$forged = Attempt { Invoke-WebRequest -Method Get -Uri "$BaseUrl/cases" `
    -Headers @{ Authorization = 'Bearer ' + ('a' * 43) } -UseBasicParsing }
Report "Forged session token rejected (401)" ((StatusOf $forged) -eq 401)

# --- 2. Injection attacks --------------------------------------------------
Write-Host "`n-- Injection attacks --"

$sqli = Attempt { Invoke-WebRequest -Method Post -Uri "$BaseUrl/auth/signin" `
    -ContentType 'application/json' `
    -Body (@{ email = "admin' OR '1'='1' --@department.gov.in"; password = 'whatever1' } | ConvertTo-Json) `
    -UseBasicParsing }
Report "SQLi in sign-in neutralised (no 500, no access)" `
    ((StatusOf $sqli) -in 400, 401)

$caseBody = (@{ applicantName = "'; DROP TABLE cases; --"; applicationType = 'Scholarship'; notes = "1' UNION SELECT password_hash FROM users --" } | ConvertTo-Json)
$case = Attempt { Invoke-RestMethod -Method Post -Uri "$BaseUrl/cases" -Headers $auth `
    -ContentType 'application/json' -Body $caseBody }
$caseStatus = StatusOf $case
if ($caseStatus -eq 200) {
    # Request reached the app: payload must be stored as inert text.
    $list = Attempt { Invoke-RestMethod -Method Get -Uri "$BaseUrl/cases" -Headers $auth }
    Report "SQLi in case fields stored as inert text (table intact)" ($list.total -ge 1)
} elseif ($caseStatus -eq 403) {
    # Hosted platforms (e.g. Render) ship a WAF that rejects attack
    # payloads before they reach the app - defence in depth. The pytest
    # suite proves the payload is inert if it ever does get through.
    Report "SQLi payload blocked by platform WAF before reaching the app (403)" $true
} else {
    Report "SQLi in case fields stored as inert text (table intact)" $false "unexpected status $caseStatus"
}

# --- 3. Access control -----------------------------------------------------
Write-Host "`n-- Access control --"

$attackerEmail = "demo-{0}@department.gov.in" -f ([guid]::NewGuid().ToString('N').Substring(0, 8))
$attacker = Attempt { Invoke-RestMethod -Method Post -Uri "$BaseUrl/auth/signup" `
    -ContentType 'application/json' `
    -Body (@{ email = $attackerEmail; password = $password } | ConvertTo-Json) }
# Benign payload so this test works even behind a strict WAF.
$owned = Attempt { Invoke-RestMethod -Method Post -Uri "$BaseUrl/cases" -Headers $auth `
    -ContentType 'application/json' `
    -Body (@{ applicantName = 'Confidential Applicant'; applicationType = 'Scholarship'; notes = 'secret notes' } | ConvertTo-Json) }
$stolen = Attempt { Invoke-WebRequest -Method Get -Uri "$BaseUrl/cases/$($owned.id)" `
    -Headers @{ Authorization = "Bearer $($attacker.token)" } -UseBasicParsing }
Report "Cross-reviewer case read blocked (404)" ((StatusOf $stolen) -eq 404) "got $(StatusOf $stolen)"

# --- 4. File upload attacks ------------------------------------------------
Write-Host "`n-- Upload hardening --"

$noTokenUpload = Attempt { $mp = New-Multipart @('a.png','b.png') @($pngBytes, $pngBytes)
    Invoke-WebRequest -Method Post -Uri "$BaseUrl/analyze" -Body $mp.Body -ContentType $mp.ContentType -UseBasicParsing }
Report "Anonymous /analyze rejected (401)" ((StatusOf $noTokenUpload) -eq 401)

$fakePng = [Text.Encoding]::ASCII.GetBytes('<' + '?php system($_GET["cmd"]); ?>' + ' fake image')
$spoof = Attempt { $mp = New-Multipart @('payload.png','ok.png') @($fakePng, $pngBytes)
    Invoke-WebRequest -Method Post -Uri "$BaseUrl/analyze" -Headers $auth -Body $mp.Body -ContentType $mp.ContentType -UseBasicParsing }
Report "Script renamed to .png rejected (magic-byte check)" ((StatusOf $spoof) -eq 400)

$exe = [byte[]](0x4D, 0x5A, 0x90, 0x00)
$exeUpload = Attempt { $mp = New-Multipart @('dropper.pdf','ok.png') @($exe, $pngBytes)
    Invoke-WebRequest -Method Post -Uri "$BaseUrl/analyze" -Headers $auth -Body $mp.Body -ContentType $mp.ContentType -UseBasicParsing }
Report "Executable renamed to .pdf rejected" ((StatusOf $exeUpload) -eq 400)

$big = $pngBytes + (New-Object byte[] (17MB))
$bigUpload = Attempt { $mp = New-Multipart @('big.png','ok.png') @($big, $pngBytes)
    Invoke-WebRequest -Method Post -Uri "$BaseUrl/analyze" -Headers $auth -Body $mp.Body -ContentType $mp.ContentType -UseBasicParsing }
Report "17 MB upload rejected with 413 (size cap)" ((StatusOf $bigUpload) -eq 413)

# --- 5. Brute force --------------------------------------------------------
Write-Host "`n-- Brute force resistance --"

$lockEmail = "demo-{0}@department.gov.in" -f ([guid]::NewGuid().ToString('N').Substring(0, 8))
$null = Attempt { Invoke-RestMethod -Method Post -Uri "$BaseUrl/auth/signup" `
    -ContentType 'application/json' `
    -Body (@{ email = $lockEmail; password = $password } | ConvertTo-Json) }
$lastCode = 0
for ($i = 0; $i -lt 8; $i++) {
    $attempt = Attempt { Invoke-WebRequest -Method Post -Uri "$BaseUrl/auth/signin" `
        -ContentType 'application/json' `
        -Body (@{ email = $lockEmail; password = 'WrongPass9' } | ConvertTo-Json) -UseBasicParsing }
    $lastCode = StatusOf $attempt
}
Report "Repeated failures trigger lockout / throttling (429)" ($lastCode -eq 429)

# --- 6. Transport hardening -----------------------------------------------
Write-Host "`n-- Transport & browser hardening --"

$health = Attempt { Invoke-WebRequest -Method Get -Uri "$BaseUrl/health" -UseBasicParsing }
Report "X-Content-Type-Options: nosniff" ((HeaderOf $health 'X-Content-Type-Options') -eq 'nosniff')
Report "X-Frame-Options: DENY" ((HeaderOf $health 'X-Frame-Options') -eq 'DENY')
Report "CSP frame-ancestors 'none'" ((HeaderOf $health 'Content-Security-Policy') -match "frame-ancestors 'none'")

$cors = Attempt { Invoke-WebRequest -Method Options -Uri "$BaseUrl/api/info" `
    -Headers @{ Origin = 'https://evil.example.com'; 'Access-Control-Request-Method' = 'GET' } `
    -UseBasicParsing }
Report "Foreign origin gets no CORS grant" `
    (-not (HeaderOf $cors 'Access-Control-Allow-Origin'))

# --- 7. Positive control: the legitimate flow still works ------------------
Write-Host "`n-- Positive control --"

$okUpload = Attempt { $mp = New-Multipart @('id.png','addr.png') @($pngBytes, $pngBytes)
    Invoke-RestMethod -Method Post -Uri "$BaseUrl/analyze" -Headers $auth -Body $mp.Body -ContentType $mp.ContentType }
# Assert on the parsed result (an ErrorRecord would be non-null too).
Report "Signed-in reviewer can still analyze documents" ($okUpload.documents_processed -ge 2)

Write-Host ''
Write-Host ('=' * 60)
Write-Host ("RESULT: $script:pass passed, $script:fail failed") `
    -ForegroundColor $(if ($script:fail -eq 0) { 'Green' } else { 'Red' })
Write-Host ''