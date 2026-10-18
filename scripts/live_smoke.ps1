# Live end-to-end smoke test for Alya VPN (Windows).
#
# Starts a local HTTP target on the runner's own non-loopback IPv4 address
# (loopback targets always bypass the tunnel by design), then proves through
# a real server+client pair:
#   1. SOCKS5 tunneled fetch and HTTP CONNECT fetch (mode all)
#   2. split-tunnel include: curl tunnels, an unknown process goes direct
#   3. split-tunnel exclude: the reverse
# It also asserts /healthz reports the version from alya.toml (drift guard)
# and exercises the documented config/*.toml parsing (auto-loaded from cwd).
param([string]$Bin = ".\alya-vpn.exe")

$ErrorActionPreference = "Stop"

$SrvPort    = 51999
$HealthPort = 18099
$HttpPort   = 18777
$ProxyAll   = 11180
$ProxyInc   = 11190
$ProxyExc   = 11200
$Psk        = "ci_smoke_psk_2026"
$Expected   = "alya-vpn-live-ok"

$TmpRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
$Tmp = Join-Path $TmpRoot "vpn-live-smoke"
Remove-Item $Tmp -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $Tmp -Force | Out-Null

$SrvLog  = Join-Path $Tmp "server.log"
$HttpLog = Join-Path $Tmp "http.log"
$Procs = @()
$Jobs = @()

function Start-Bg {
    param([string]$FilePath, [string[]]$ArgList, [string]$Log)
    $p = Start-Process -FilePath $FilePath -ArgumentList $ArgList -PassThru `
        -WindowStyle Hidden -RedirectStandardOutput $Log -RedirectStandardError "$Log.err"
    $script:Procs += $p
    return $p
}

function Start-HttpTarget {
    # Minimal HTTP/1.1 target: fixed body for every request. Pure PowerShell,
    # no python dependency; runs in a background job.
    param([int]$Port, [string]$Body)
    $job = Start-Job -ArgumentList @($Port, $Body) -ScriptBlock {
        param([int]$Port, [string]$Body)
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $Port)
        $listener.Start()
        $bodyBytes = [System.Text.Encoding]::ASCII.GetBytes($Body)
        $header = "HTTP/1.1 200 OK`r`nContent-Type: text/plain; charset=utf-8`r`nContent-Length: $($bodyBytes.Length)`r`nConnection: close`r`n`r`n"
        $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($header)
        while ($true) {
            $client = $listener.AcceptTcpClient()
            try {
                $stream = $client.GetStream()
                $buffer = [byte[]]::new(4096)
                $null = $stream.Read($buffer, 0, $buffer.Length)
                $stream.Write($headerBytes, 0, $headerBytes.Length)
                $stream.Write($bodyBytes, 0, $bodyBytes.Length)
                $stream.Flush()
            } catch { }
            finally { $client.Close() }
        }
    }
    $script:Jobs += $job
    return $job
}

function Stop-Everything {
    foreach ($p in $script:Procs) {
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    }
    $script:Procs = @()
    foreach ($j in $script:Jobs) {
        Stop-Job $j -ErrorAction SilentlyContinue
        Remove-Job $j -Force -ErrorAction SilentlyContinue
    }
    $script:Jobs = @()
}

function Fail {
    param([string]$Msg)
    Write-Host ""
    Write-Host "SMOKE FAIL: $Msg"
    if (Test-Path $SrvLog)  { Write-Host "--- server log (tail) ---"; Get-Content $SrvLog -Tail 40 }
    if (Test-Path $HttpLog) { Write-Host "--- http log (tail) ---";  Get-Content $HttpLog -Tail 10 }
    Get-ChildItem (Join-Path $Tmp "client_*.log") -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "--- $($_.Name) (tail) ---"
        Get-Content $_.FullName -Tail 60
    }
    Stop-Everything
    exit 1
}

function Invoke-CurlBody {
    param([string[]]$CurlArgs)
    $out = & curl.exe @CurlArgs 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    return ($out -join "`n")
}

function Test-LogMatch {
    param([string]$LogFile, [string]$Pattern)
    return [bool](Select-String -Path $LogFile -Pattern $Pattern -Quiet -ErrorAction SilentlyContinue)
}

function Count-LogMatch {
    param([string]$LogFile, [string]$Pattern)
    return @(Select-String -Path $LogFile -Pattern $Pattern -ErrorAction SilentlyContinue).Count
}

if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) { Fail "curl.exe is not available" }

# --- runner's own non-loopback IPv4 (the tunnel-proof target) ---
$Tip = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.IPAddress -notlike "169.254.*" -and $_.AddressState -eq "Preferred" } |
    Select-Object -First 1).IPAddress
if (-not $Tip) { Fail "could not determine the runner's non-loopback IPv4" }
Write-Host "== target: http://${Tip}:${HttpPort} (non-loopback = tunnel proof)"

# --- expected app version from the manifest (healthz drift guard) ---
$verLine = Select-String -Path "alya.toml" -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
if (-not $verLine) { Fail "could not read version from alya.toml" }
$AppVersion = $verLine.Matches[0].Groups[1].Value

# --- local HTTP target ---
Start-HttpTarget -Port $HttpPort -Body $Expected | Out-Null
$httpOk = $false
for ($i = 0; $i -lt 20; $i++) {
    if ((Invoke-CurlBody @("-sS","--max-time","5","http://127.0.0.1:$HttpPort/ok.txt")) -eq $Expected) { $httpOk = $true; break }
    Start-Sleep -Seconds 1
}
if (-not $httpOk) { Fail "local HTTP target did not come up" }
Write-Host "ok: local HTTP target serving on 0.0.0.0:$HttpPort"

# --- VPN server (also exercises the documented config/server.toml) ---
Start-Bg -FilePath $Bin -ArgList @("server","--bind","127.0.0.1","--port","$SrvPort","--pass",$Psk,
    "--block-lan","false","--health-port","$HealthPort","--log-level","debug") -Log $SrvLog | Out-Null
$hc = $null
for ($i = 0; $i -lt 30; $i++) {
    $hc = Invoke-CurlBody @("-sS","--max-time","5","http://127.0.0.1:$HealthPort/healthz")
    if ($hc) { break }
    Start-Sleep -Seconds 1
}
if (-not $hc -or -not $hc.Contains('"status":"ok"')) { Fail "healthz did not come up" }
if (-not $hc.Contains('"version":"' + $AppVersion + '"')) {
    Fail "healthz version != alya.toml ($AppVersion): $hc"
}
Write-Host "ok: healthz reports version $AppVersion"

function Start-Client {
    param([int]$ProxyPort, [string]$Mode, [string]$LogFile, [string]$Apps = "")
    $a = @("client","--bind","127.0.0.1","--server","127.0.0.1","--port","$SrvPort",
        "--proxy","$ProxyPort","--pass",$Psk,"--mode",$Mode,"--bypass-lan","false",
        "--no-system-proxy","--log-direct","--log-level","debug")
    if ($Apps) { $a += @("--apps",$Apps) }
    Start-Bg -FilePath $Bin -ArgList $a -Log $LogFile | Out-Null
}

function Wait-Tunnel {
    param([int]$ProxyPort)
    for ($i = 0; $i -lt 60; $i++) {
        $b = Invoke-CurlBody @("-sS","--max-time","15","--socks5","127.0.0.1:$ProxyPort","http://${Tip}:${HttpPort}/ok.txt")
        if ($b -eq $Expected) { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Wait-TunnelProbe {
    # Like Wait-Tunnel but through the given probe binary (notcurl): needed in
    # mode=exclude, where real curl bypasses the tunnel and cannot prove it.
    param([string]$ProbeBin, [int]$ProxyPort)
    for ($i = 0; $i -lt 60; $i++) {
        $b = & $ProbeBin -sS --max-time 15 --socks5 "127.0.0.1:$ProxyPort" "http://${Tip}:${HttpPort}/ok.txt" 2>$null
        if ($LASTEXITCODE -eq 0 -and ($b -join "`n") -eq $Expected) { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}

# --- phase ALL: every target tunnels ---
$ClientAll = Join-Path $Tmp "client_all.log"
Start-Client -ProxyPort $ProxyAll -Mode "all" -LogFile $ClientAll
if (-not (Wait-Tunnel -ProxyPort $ProxyAll)) { Fail "mode=all: tunneled fetch never succeeded" }
if (-not (Test-LogMatch $ClientAll "\[TUNNEL\] \[curl.*-> ${Tip}:${HttpPort}")) { Fail "mode=all: no [TUNNEL] log line" }
if (-not (Test-LogMatch $SrvLog "\[FORWARD\] Connected: Channel .* -> ${Tip}:${HttpPort}")) { Fail "mode=all: no server [FORWARD] line" }
Write-Host "ok: mode=all SOCKS5 fetch tunneled (client [TUNNEL] + server [FORWARD])"

# HTTP CONNECT on the same port
$before = Count-LogMatch $ClientAll "\[TUNNEL\] \[curl.*-> ${Tip}:${HttpPort}"
$connectBody = Invoke-CurlBody @("-sS","--max-time","15","--proxytunnel","-x","http://127.0.0.1:$ProxyAll","http://${Tip}:${HttpPort}/ok.txt")
if (-not $connectBody) { Fail "HTTP CONNECT fetch failed" }
if ($connectBody -ne $Expected) { Fail "HTTP CONNECT body mismatch: $connectBody" }
$after = Count-LogMatch $ClientAll "\[TUNNEL\] \[curl.*-> ${Tip}:${HttpPort}"
if ($after -le $before) { Fail "HTTP CONNECT did not tunnel (TUNNEL count $before -> $after)" }
Write-Host "ok: HTTP CONNECT fetch tunneled"

# notcurl = curl.exe copied under an unrecognized name (split-tunnel probe)
$NotCurl = Join-Path $Tmp "notcurl.exe"
Copy-Item (Get-Command curl.exe).Source $NotCurl -Force

# --- phase INCLUDE: only curl tunnels ---
$ClientInc = Join-Path $Tmp "client_inc.log"
Start-Client -ProxyPort $ProxyInc -Mode "include" -Apps "curl,curl.exe" -LogFile $ClientInc
if (-not (Wait-Tunnel -ProxyPort $ProxyInc)) { Fail "mode=include: tunnel never came up" }
$body = & $NotCurl -sS --max-time 15 --socks5 "127.0.0.1:$ProxyInc" "http://${Tip}:${HttpPort}/ok.txt" 2>$null
if ($LASTEXITCODE -ne 0) { Fail "mode=include: notcurl fetch failed" }
if (($body -join "`n") -ne $Expected) { Fail "mode=include: notcurl body mismatch" }
if (-not (Test-LogMatch $ClientInc "\[DIRECT\] \[notcurl")) { Fail "mode=include: notcurl was not DIRECT" }
if (Test-LogMatch $ClientInc "\[TUNNEL\] \[notcurl") { Fail "mode=include: notcurl was tunneled" }
Write-Host "ok: mode=include (curl tunnels, notcurl bypasses)"

# --- phase EXCLUDE: everything but curl tunnels ---
$ClientExc = Join-Path $Tmp "client_exc.log"
Start-Client -ProxyPort $ProxyExc -Mode "exclude" -Apps "curl,curl.exe" -LogFile $ClientExc
if (-not (Wait-TunnelProbe -ProbeBin $NotCurl -ProxyPort $ProxyExc)) { Fail "mode=exclude: tunnel never came up" }
$body = Invoke-CurlBody @("-sS","--max-time","15","--socks5","127.0.0.1:$ProxyExc","http://${Tip}:${HttpPort}/ok.txt")
if ($body -ne $Expected) { Fail "mode=exclude: curl fetch failed or body mismatch" }
if (-not (Test-LogMatch $ClientExc "\[DIRECT\] \[curl")) { Fail "mode=exclude: curl was not DIRECT" }
$body = & $NotCurl -sS --max-time 15 --socks5 "127.0.0.1:$ProxyExc" "http://${Tip}:${HttpPort}/ok.txt" 2>$null
if ($LASTEXITCODE -ne 0) { Fail "mode=exclude: notcurl fetch failed" }
if (($body -join "`n") -ne $Expected) { Fail "mode=exclude: notcurl body mismatch" }
if (-not (Test-LogMatch $ClientExc "\[TUNNEL\] \[notcurl.*-> ${Tip}:${HttpPort}")) { Fail "mode=exclude: notcurl was not tunneled" }
Write-Host "ok: mode=exclude (curl bypasses, notcurl tunnels)"

Stop-Everything
Write-Host "SMOKE PASS: live tunnel, HTTP CONNECT, split-tunnel include/exclude verified"
exit 0
