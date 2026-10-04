# ============================================================
# Token Security Auditor - Lab Startup Script
# ============================================================
#
# Project structure:
#
# token_security_system\
# ├── .env
# ├── .venv\
# ├── app\
# ├── analyzer\
# ├── target_app\
# └── scripts\
#     └── start_lab.ps1
#
# Configuration:
#   All hosts, ports, URLs and API keys are loaded from .env
#
# Processes:
#   1. Auditor Flask application
#   2. Target application
#   3. mitmproxy reverse proxy
#
# TLS:
#   Client -> mitmproxy -> target_app
#
#   target_app uses a certificate signed by the mkcert Root CA.
#   mitmproxy explicitly trusts that Root CA when connecting
#   to the upstream target application.
#
# ============================================================

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Token Security Auditor - Lab Startup" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""


# ============================================================
# 1. Determine project root
# ============================================================

$ScriptsDir = $PSScriptRoot
$ProjectRoot = Split-Path -Parent $ScriptsDir

Write-Host "[INFO] Scripts directory : $ScriptsDir" -ForegroundColor DarkGray
Write-Host "[INFO] Project root      : $ProjectRoot" -ForegroundColor DarkGray


# ============================================================
# 2. Check project structure
# ============================================================

$EnvFile = Join-Path $ProjectRoot ".env"
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$TargetDir = Join-Path $ProjectRoot "target_app"
$TargetApp = Join-Path $TargetDir "app.py"
$AddonPath = Join-Path $ProjectRoot "analyzer\mitm_addon.py"

if (-not (Test-Path $EnvFile)) {
    throw "[ERROR] .env not found: $EnvFile"
}

if (-not (Test-Path $VenvPython)) {
    throw "[ERROR] Python virtual environment not found: $VenvPython"
}

if (-not (Test-Path $TargetApp)) {
    throw "[ERROR] Target application not found: $TargetApp"
}

if (-not (Test-Path $AddonPath)) {
    throw "[ERROR] mitmproxy addon not found: $AddonPath"
}


# ============================================================
# 3. Load .env
# ============================================================

Write-Host "[INFO] Loading environment from .env..." -ForegroundColor Yellow

Get-Content $EnvFile | ForEach-Object {

    $line = $_.Trim()

    # Skip empty lines
    if ([string]::IsNullOrWhiteSpace($line)) {
        return
    }

    # Skip comments
    if ($line.StartsWith("#")) {
        return
    }

    # Only process KEY=VALUE lines
    if ($line -notmatch "^\s*([^=]+?)\s*=\s*(.*)$") {
        return
    }

    $key = $matches[1].Trim()
    $value = $matches[2].Trim()

    # Remove surrounding quotes
    if (
        ($value.StartsWith('"') -and $value.EndsWith('"')) -or
        ($value.StartsWith("'") -and $value.EndsWith("'"))
    ) {
        $value = $value.Substring(1, $value.Length - 2)
    }

    Set-Item -Path "Env:$key" -Value $value
}


# ============================================================
# 4. Read network configuration
# ============================================================

$AuditorHost = $env:AUDITOR_HOST
$AuditorPort = [int]$env:AUDITOR_PORT

$TargetHost = $env:TARGET_HOST
$TargetPort = [int]$env:TARGET_PORT

$MitmproxyHost = $env:MITMPROXY_HOST
$MitmproxyPort = [int]$env:MITMPROXY_PORT


# ============================================================
# 5. Read application URLs
# ============================================================

$BaseUrl = $env:BASE_URL
$TargetUrl = $env:TARGET_URL

$CaptureApiUrl = $env:AUDITOR_CAPTURE_API_URL
$AttackResultsApiUrl = $env:AUDITOR_ATTACK_RESULTS_API_URL


# ============================================================
# 6. Validate required environment variables
# ============================================================

$RequiredVariables = @(
    "AUDITOR_HOST",
    "AUDITOR_PORT",
    "TARGET_HOST",
    "TARGET_PORT",
    "MITMPROXY_HOST",
    "MITMPROXY_PORT",

    "BASE_URL",
    "TARGET_URL",

    "AUDITOR_CAPTURE_API_URL",
    "AUDITOR_ATTACK_RESULTS_API_URL",

    "ATTACK_SIMULATOR_API_KEY",
    "MITMPROXY_CAPTURE_API_KEY"
)

foreach ($VariableName in $RequiredVariables) {

    $VariableValue = [Environment]::GetEnvironmentVariable($VariableName)

    if ([string]::IsNullOrWhiteSpace($VariableValue)) {
        throw "[ERROR] Required environment variable is missing: $VariableName"
    }
}


# ============================================================
# 7. Validate TARGET_URL
# ============================================================

try {
    $TargetUri = [System.Uri]$TargetUrl
}
catch {
    throw "[ERROR] Invalid TARGET_URL: $TargetUrl"
}

if (-not $TargetUri.IsAbsoluteUri) {
    throw "[ERROR] TARGET_URL must be an absolute URL: $TargetUrl"
}

if ($TargetUri.Scheme -notin @("http", "https")) {
    throw "[ERROR] TARGET_URL must use http:// or https://: $TargetUrl"
}

if ([string]::IsNullOrWhiteSpace($TargetUri.Host)) {
    throw "[ERROR] TARGET_URL does not contain a valid host: $TargetUrl"
}

$TargetScheme = $TargetUri.Scheme.ToLowerInvariant()


# ============================================================
# 8. Configure TLS trust
# ============================================================

$MitmproxyUpstreamCA = $null

if ($TargetScheme -eq "https") {

    Write-Host ""
    Write-Host "[INFO] TARGET_URL uses HTTPS." -ForegroundColor Yellow
    Write-Host "[INFO] Configuring mitmproxy upstream TLS trust..." -ForegroundColor Yellow

    if ([string]::IsNullOrWhiteSpace($env:MITMPROXY_UPSTREAM_CA)) {
        throw "[ERROR] MITMPROXY_UPSTREAM_CA is required when TARGET_URL uses HTTPS."
    }

    $MitmproxyUpstreamCA = $env:MITMPROXY_UPSTREAM_CA

    if (-not [System.IO.Path]::IsPathRooted($MitmproxyUpstreamCA)) {
        $MitmproxyUpstreamCA = Join-Path `
            $ProjectRoot `
            $MitmproxyUpstreamCA
    }

    if (-not (Test-Path $MitmproxyUpstreamCA -PathType Leaf)) {
        throw "[ERROR] mitmproxy upstream CA not found: $MitmproxyUpstreamCA"
    }

    Write-Host "[OK] mitmproxy upstream CA found:" -ForegroundColor Green
    Write-Host "     $MitmproxyUpstreamCA" -ForegroundColor DarkGray
}

$MitmproxyAuditorCA = $null

if ([string]::IsNullOrWhiteSpace($env:MITMPROXY_AUDITOR_CA)) {
    throw "[ERROR] MITMPROXY_AUDITOR_CA is required."
}

$MitmproxyAuditorCA = $env:MITMPROXY_AUDITOR_CA

if (-not [System.IO.Path]::IsPathRooted($MitmproxyAuditorCA)) {
    $MitmproxyAuditorCA = Join-Path `
        $ProjectRoot `
        $MitmproxyAuditorCA
}

if (-not (Test-Path $MitmproxyAuditorCA -PathType Leaf)) {
    throw "[ERROR] mitmproxy Auditor CA not found: $MitmproxyAuditorCA"
}

Write-Host "[OK] mitmproxy Auditor CA found:" -ForegroundColor Green
Write-Host "     $MitmproxyAuditorCA" -ForegroundColor DarkGray

# ============================================================
# 9. Validate network configuration
# ============================================================

if ($AuditorPort -lt 1 -or $AuditorPort -gt 65535) {
    throw "[ERROR] Invalid AUDITOR_PORT: $AuditorPort"
}

if ($TargetPort -lt 1 -or $TargetPort -gt 65535) {
    throw "[ERROR] Invalid TARGET_PORT: $TargetPort"
}

if ($MitmproxyPort -lt 1 -or $MitmproxyPort -gt 65535) {
    throw "[ERROR] Invalid MITMPROXY_PORT: $MitmproxyPort"
}


# ============================================================
# 10. Display configuration
# ============================================================

Write-Host ""
Write-Host "------------------------------------------------------------" -ForegroundColor DarkCyan
Write-Host "Lab configuration" -ForegroundColor DarkCyan
Write-Host "------------------------------------------------------------" -ForegroundColor DarkCyan

Write-Host "Auditor   : ${AuditorHost}:${AuditorPort}"
Write-Host "Target    : ${TargetHost}:${TargetPort}"
Write-Host "mitmproxy : ${MitmproxyHost}:${MitmproxyPort}"

Write-Host ""
Write-Host "BASE_URL  : $BaseUrl"
Write-Host "TARGET_URL: $TargetUrl"

if ($TargetScheme -eq "https") {
    Write-Host "Upstream TLS CA: $MitmproxyUpstreamCA"
}

Write-Host "Auditor TLS CA : $MitmproxyAuditorCA"

Write-Host ""
Write-Host "Capture API       : $CaptureApiUrl"
Write-Host "Attack Results API: $AttackResultsApiUrl"

Write-Host "------------------------------------------------------------" -ForegroundColor DarkCyan
Write-Host ""


# ============================================================
# 11. Helper: check whether a TCP port is already listening
# ============================================================

function Test-PortInUse {
    param (
        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    try {
        $Connection = Get-NetTCPConnection `
            -LocalPort $Port `
            -State Listen `
            -ErrorAction SilentlyContinue

        return $null -ne $Connection
    }
    catch {
        return $false
    }
}


# ============================================================
# 12. Check required ports
# ============================================================

$PortsToCheck = @(
    @{
        Name = "Auditor"
        Port = $AuditorPort
    },
    @{
        Name = "Target"
        Port = $TargetPort
    },
    @{
        Name = "mitmproxy"
        Port = $MitmproxyPort
    }
)

foreach ($PortInfo in $PortsToCheck) {

    if (Test-PortInUse -Port $PortInfo.Port) {

        Write-Host ""
        Write-Host "[ERROR] Port $($PortInfo.Port) is already in use ($($PortInfo.Name))." -ForegroundColor Red

        $ExistingConnections = Get-NetTCPConnection `
            -LocalPort $PortInfo.Port `
            -State Listen `
            -ErrorAction SilentlyContinue

        if ($ExistingConnections) {

            foreach ($Connection in $ExistingConnections) {

                $ProcessId = $Connection.OwningProcess

                try {
                    $Process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue

                    if ($Process) {
                        Write-Host "        PID  : $ProcessId" -ForegroundColor Yellow
                        Write-Host "        Name : $($Process.ProcessName)" -ForegroundColor Yellow
                    }
                }
                catch {
                    Write-Host "        PID  : $ProcessId" -ForegroundColor Yellow
                }
            }
        }

        Write-Host ""
        Write-Host "Stop the process using this port and run the script again." -ForegroundColor Yellow

        exit 1
    }
}


# ============================================================
# 13. Helper: start process
# ============================================================

function Start-LabProcess {

    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    Write-Host "[START] $Name" -ForegroundColor Green
    Write-Host "        Executable : $FilePath" -ForegroundColor DarkGray
    Write-Host "        Working dir: $WorkingDirectory" -ForegroundColor DarkGray

    $Process = Start-Process `
        -FilePath $FilePath `
        -WorkingDirectory $WorkingDirectory `
        -ArgumentList $Arguments `
        -PassThru

    if (-not $Process) {
        throw "[ERROR] Failed to start $Name"
    }

    Write-Host "        PID         : $($Process.Id)" -ForegroundColor DarkGray

    return $Process
}


# ============================================================
# 14. Start processes
# ============================================================

$AuditorProcess = $null
$TargetProcess = $null
$MitmproxyProcess = $null

try {

    # ========================================================
    # Start Auditor
    # ========================================================

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " Starting Auditor" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    $AuditorProcess = Start-LabProcess `
		-FilePath $VenvPython `
		-WorkingDirectory $ProjectRoot `
		-Arguments @(
			"run.py"
		) `
		-Name "Auditor"

    Start-Sleep -Seconds 2


    # ========================================================
    # Verify Auditor
    # ========================================================

    if (-not (Test-PortInUse -Port $AuditorPort)) {
        throw "[ERROR] Auditor did not start listening on port $AuditorPort."
    }

    Write-Host ""
    Write-Host "[OK] Auditor is listening on ${AuditorHost}:${AuditorPort}" -ForegroundColor Green


    # ========================================================
    # Start Target Application
    # ========================================================

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " Starting Target Application" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    $TargetProcess = Start-LabProcess `
        -FilePath $VenvPython `
        -WorkingDirectory $TargetDir `
        -Arguments @(
            "app.py"
        ) `
        -Name "Target Application"

    Start-Sleep -Seconds 2


    # ========================================================
    # Verify Target
    # ========================================================

    if (-not (Test-PortInUse -Port $TargetPort)) {
        throw "[ERROR] Target application did not start listening on port $TargetPort."
    }

    Write-Host ""
    Write-Host "[OK] Target application is listening on ${TargetHost}:${TargetPort}" -ForegroundColor Green


    # ========================================================
    # Start mitmproxy
    # ========================================================

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " Starting mitmproxy" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    $MitmproxyArguments = @(
		"--mode",
		"reverse:$TargetUrl",
		"--listen-host",
		$MitmproxyHost,
		"--listen-port",
		$MitmproxyPort,
		"-s",
		$AddonPath,
		"--set",
		"target_api=$CaptureApiUrl",
		"--set",
		"ingest_key=$env:MITMPROXY_CAPTURE_API_KEY",
		"--set",
		"auditor_ca=$MitmproxyAuditorCA"
	)

    if ($TargetScheme -eq "https") {
		$MitmproxyArguments += @(
			"--set",
			"ssl_verify_upstream_trusted_ca=$MitmproxyUpstreamCA"
		)

		Write-Host "[INFO] mitmproxy upstream certificate verification: ENABLED" -ForegroundColor Green
		Write-Host "[INFO] Trusted CA: $MitmproxyUpstreamCA" -ForegroundColor DarkGray
	}

    $MitmproxyProcess = Start-LabProcess `
        -FilePath "mitmdump" `
        -WorkingDirectory $ProjectRoot `
        -Arguments $MitmproxyArguments `
        -Name "mitmproxy"

    Start-Sleep -Seconds 3


    # ========================================================
    # Verify mitmproxy
    # ========================================================

    if (-not (Test-PortInUse -Port $MitmproxyPort)) {
        throw "[ERROR] mitmproxy did not start listening on port $MitmproxyPort."
    }

    Write-Host ""
    Write-Host "[OK] mitmproxy is listening on ${MitmproxyHost}:${MitmproxyPort}" -ForegroundColor Green


    # ========================================================
    # Final information
    # ========================================================

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host " LAB STARTED SUCCESSFULLY" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green

    Write-Host ""
    Write-Host "Auditor:" -ForegroundColor Cyan
    Write-Host "  $BaseUrl"

    Write-Host ""
    Write-Host "Target application:" -ForegroundColor Cyan
    Write-Host "  $TargetUrl"

    Write-Host ""
    Write-Host "mitmproxy:" -ForegroundColor Cyan
    Write-Host "  https://${MitmproxyHost}:${MitmproxyPort}"

    Write-Host ""
    Write-Host "Processes:" -ForegroundColor Cyan
    Write-Host "  Auditor   PID: $($AuditorProcess.Id)"
    Write-Host "  Target    PID: $($TargetProcess.Id)"
    Write-Host "  mitmproxy PID: $($MitmproxyProcess.Id)"

    Write-Host ""
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host "Test request through mitmproxy:" -ForegroundColor DarkCyan
    Write-Host "------------------------------------------------------------"

    Write-Host ""

    if ($TargetScheme -eq "https") {

        Write-Host "curl.exe --ssl-no-revoke `"https://${MitmproxyHost}:${MitmproxyPort}/unsafe/url-token?token=DEMO-TOKEN`"" -ForegroundColor Yellow
    }
    else {

        Write-Host "curl.exe `"http://${MitmproxyHost}:${MitmproxyPort}/unsafe/url-token?token=DEMO-TOKEN`"" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Open Auditor:" -ForegroundColor DarkCyan
    Write-Host "  $BaseUrl"

    Write-Host ""
    Write-Host "Press Ctrl+C to stop this script." -ForegroundColor Gray
    Write-Host ""


    # ========================================================
    # Keep script alive
    # ========================================================

    while ($true) {

        Start-Sleep -Seconds 5

        # Check Auditor
        if (-not (Test-PortInUse -Port $AuditorPort)) {
            Write-Host "[WARN] Auditor is no longer listening on port $AuditorPort." -ForegroundColor Red
        }

        # Check Target
        if (-not (Test-PortInUse -Port $TargetPort)) {
            Write-Host "[WARN] Target is no longer listening on port $TargetPort." -ForegroundColor Red
        }

        # Check mitmproxy
        if (-not (Test-PortInUse -Port $MitmproxyPort)) {
            Write-Host "[WARN] mitmproxy is no longer listening on port $MitmproxyPort." -ForegroundColor Red
        }
    }
}
catch {

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host " LAB STARTUP FAILED" -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red

    Write-Host ""
    Write-Host $_.Exception.Message -ForegroundColor Red


    # ========================================================
    # Cleanup already started processes
    # ========================================================

    Write-Host ""
    Write-Host "[INFO] Cleaning up started processes..." -ForegroundColor Yellow

    if ($MitmproxyProcess) {

        try {
            Stop-Process -Id $MitmproxyProcess.Id -Force -ErrorAction SilentlyContinue
            Write-Host "[STOP] mitmproxy PID $($MitmproxyProcess.Id)" -ForegroundColor Yellow
        }
        catch {}
    }

    if ($TargetProcess) {

        try {
            Stop-Process -Id $TargetProcess.Id -Force -ErrorAction SilentlyContinue
            Write-Host "[STOP] Target PID $($TargetProcess.Id)" -ForegroundColor Yellow
        }
        catch {}
    }

    if ($AuditorProcess) {

        try {
            Stop-Process -Id $AuditorProcess.Id -Force -ErrorAction SilentlyContinue
            Write-Host "[STOP] Auditor PID $($AuditorProcess.Id)" -ForegroundColor Yellow
        }
        catch {}
    }

    Write-Host ""
    exit 1
}

