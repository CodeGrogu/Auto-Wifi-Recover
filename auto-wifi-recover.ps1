# Requires: Windows 11, PowerShell 5+, WLAN service running, Wi-Fi profile already saved
# Safe defaults: 10s sampling, 3 failed checks before reconnect
# Note: On captive portal networks (hotels, coffee shops), use -UseGatewayPing to avoid
#       false reconnects when Wi-Fi is up but internet requires browser login.
# Tip:  If you have multiple profiles for the same network (2.4GHz/5GHz), ensure only your
#       preferred one has "Connect Automatically" enabled to avoid Windows fighting the script.

param(
    [int]$SampleSeconds = 10,
    [int]$MaxFailures = 3,
    [string]$PingTarget = "1.1.1.1",  # change to a local router IP if you prefer
    [int]$CooldownSeconds = 120,       # minimum gap between reconnects
    [int]$MaxReconnectsPerHour = 10,   # rate-limit reconnects
    [string]$LogPath = "C:\\ProgramData\\auto-wifi-recover\\logs\\auto-wifi-recover.log",
    [string]$PreferredSsid = $null,     # optional pinned SSID to avoid "goldfish" loss
    [switch]$UseGatewayPing,            # ping default gateway instead of internet (for captive portals)
    [int]$ResumeGraceSeconds = 30,      # seconds to wait after wake-from-sleep before taking action
    [int]$PingTimeoutMs = 2000,         # ping timeout in milliseconds (increase for high-latency networks)
    [int]$PingCount = 2,                # number of ping attempts before declaring failure
    [string[]]$FallbackSsids = @(),     # ordered list of fallback SSIDs if primary fails
    [switch]$EnableToast,               # show Windows toast notifications on reconnect
    [switch]$EnableEventLog,            # write events to Windows Event Log
    [switch]$Install,                   # install as scheduled task (runs at logon)
    [switch]$Uninstall                  # remove scheduled task
)

# Minimal versioning and integrity stamp for audit trail
$ScriptVersion = "1.8.0"
$ScriptHash = try { (Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath -ErrorAction Stop).Hash } catch { "unknown" }
# Validate log path early (before elevation) for fast failure on invalid paths
$logDir = Split-Path -Parent $LogPath
if ($logDir -and -not (Test-Path -LiteralPath $logDir)) {
    try {
        New-Item -ItemType Directory -Path $logDir -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Host "FATAL: Cannot create log directory '$logDir': $_" -ForegroundColor Red
        exit 1
    }
}
# Relaunch as admin if not elevated so netsh has rights
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $argList = @('-File', "`"$PSCommandPath`"")
    foreach ($kvp in $PSBoundParameters.GetEnumerator()) {
        if ($kvp.Value -is [switch]) {
            if ($kvp.Value) { $argList += "-$($kvp.Key)" }
        } else {
            $argList += @("-$($kvp.Key)", "`"$($kvp.Value)`"")
        }
    }
    Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argList | Out-Null
    exit
}

# === Scheduled Task Management ===
$TaskName = "AutoWifiRecover"
$TaskDescription = "Monitors Wi-Fi connectivity and automatically reconnects when connection drops"

function Install-ScheduledTask {
    # Create a scheduled task that runs this script at user logon
    $scriptPath = $PSCommandPath
    
    # Build argument string preserving user's preferred parameters
    $taskArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', "`"$scriptPath`"")
    if ($PreferredSsid) { $taskArgs += @('-PreferredSsid', "`"$PreferredSsid`"") }
    if ($FallbackSsids.Count -gt 0) { $taskArgs += @('-FallbackSsids', ($FallbackSsids -join ',')) }
    if ($UseGatewayPing) { $taskArgs += '-UseGatewayPing' }
    if ($EnableToast) { $taskArgs += '-EnableToast' }
    if ($EnableEventLog) { $taskArgs += '-EnableEventLog' }
    
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ($taskArgs -join ' ')
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest -LogonType Interactive
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    
    # Remove existing task if present
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    
    try {
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $TaskDescription -ErrorAction Stop | Out-Null
        Write-Host "[success] Scheduled task '$TaskName' installed. Script will run at logon." -ForegroundColor Green
        Write-Host "          To start now: schtasks /run /tn '$TaskName'" -ForegroundColor Gray
        Write-Host "          To remove:    .\$($MyInvocation.MyCommand.Name) -Uninstall" -ForegroundColor Gray
        return $true
    } catch {
        Write-Host "[error] Failed to create scheduled task: $_" -ForegroundColor Red
        return $false
    }
}

function Uninstall-ScheduledTask {
    try {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($task) {
            # Stop if running
            if ($task.State -eq 'Running') {
                Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            }
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
            Write-Host "[success] Scheduled task '$TaskName' removed." -ForegroundColor Green
        } else {
            Write-Host "[info] Scheduled task '$TaskName' not found (already removed)." -ForegroundColor Yellow
        }
        return $true
    } catch {
        Write-Host "[error] Failed to remove scheduled task: $_" -ForegroundColor Red
        return $false
    }
}

# Handle -Install / -Uninstall and exit
if ($Install) {
    Install-ScheduledTask
    exit
}
if ($Uninstall) {
    Uninstall-ScheduledTask
    exit
}

# === Windows Event Log Integration ===
$EventLogSource = "AutoWifiRecover"
$EventLogName = "Application"

function Initialize-EventLogSource {
    if (-not $EnableEventLog) { return }
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($EventLogSource)) {
            [System.Diagnostics.EventLog]::CreateEventSource($EventLogSource, $EventLogName)
            # Source creation requires a moment to propagate
            Start-Sleep -Seconds 1
        }
    } catch {
        # May fail if not admin or source exists under different log
        Write-Log "WARN" "Could not create event log source: $_"
    }
}

function Write-EventLogEntry {
    param(
        [string]$Message,
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$EntryType = 'Information',
        [int]$EventId = 1000
    )
    if (-not $EnableEventLog) { return }
    try {
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EventId $EventId -EntryType $EntryType -Message $Message -ErrorAction Stop
    } catch {
        # Silently fail if event log not available
    }
}

# === Toast Notification ===
function Show-ToastNotification {
    param(
        [string]$Title,
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Type = 'Info'
    )
    if (-not $EnableToast) { return }
    
    try {
        # Use BurntToast module if available (richer notifications)
        if (Get-Module -ListAvailable -Name BurntToast -ErrorAction SilentlyContinue) {
            Import-Module BurntToast -ErrorAction Stop
            $icon = switch ($Type) {
                'Warning' { 'Warning' }
                'Error' { 'Error' }
                default { 'Information' }
            }
            New-BurntToastNotification -Text $Title, $Message -AppLogo $null -ErrorAction Stop
            return
        }
        
        # Fallback: Use Windows.UI.Notifications (built-in, requires assemblies)
        $null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
        $null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
        
        $template = @"
<toast>
    <visual>
        <binding template="ToastText02">
            <text id="1">$([System.Security.SecurityElement]::Escape($Title))</text>
            <text id="2">$([System.Security.SecurityElement]::Escape($Message))</text>
        </binding>
    </visual>
</toast>
"@
        $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
        $xml.LoadXml($template)
        $toast = New-Object Windows.UI.Notifications.ToastNotification $xml
        $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("AutoWifiRecover")
        $notifier.Show($toast)
    } catch {
        # Toast failed, fall back to balloon tip if possible
        $balloon = $null
        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
            $balloon = New-Object System.Windows.Forms.NotifyIcon
            $balloon.Icon = [System.Drawing.SystemIcons]::Information
            $balloon.BalloonTipTitle = $Title
            $balloon.BalloonTipText = $Message
            $balloon.BalloonTipIcon = switch ($Type) {
                'Warning' { [System.Windows.Forms.ToolTipIcon]::Warning }
                'Error' { [System.Windows.Forms.ToolTipIcon]::Error }
                default { [System.Windows.Forms.ToolTipIcon]::Info }
            }
            $balloon.Visible = $true
            $balloon.ShowBalloonTip(5000)
            Start-Sleep -Milliseconds 5100
        } catch {
            # All notification methods failed; log it
            Write-Log "WARN" "Toast notification failed: $_"
        } finally {
            if ($balloon) { $balloon.Dispose() }
        }
    }
}

# === Multi-SSID Fallback ===
function Connect-ToSsid {
    param(
        [string]$Ssid,
        [string]$InterfaceName
    )
    $output = netsh wlan connect name="$Ssid" interface="$InterfaceName" 2>&1
    $success = ($LASTEXITCODE -eq 0)
    if (-not $success) {
        Write-Log "WARN" "Failed to connect to SSID=$Ssid (exit=$LASTEXITCODE): $output"
    }
    return $success
}

function Connect-WithFallback {
    param(
        [string]$PrimarySsid,
        [string[]]$FallbackList,
        [string]$InterfaceName
    )
    # Try primary first
    if (Connect-ToSsid -Ssid $PrimarySsid -InterfaceName $InterfaceName) {
        return $PrimarySsid
    }
    
    # Try each fallback in order
    foreach ($fallback in $FallbackList) {
        if ($fallback -and $fallback -ne $PrimarySsid) {
            Write-Log "INFO" "Primary SSID failed; trying fallback: $fallback"
            Write-Host "[info] Trying fallback network: $fallback" -ForegroundColor Gray
            if (Connect-ToSsid -Ssid $fallback -InterfaceName $InterfaceName) {
                return $fallback
            }
        }
    }
    
    return $null  # All failed
}

function Ensure-LogPath {
    $dir = Split-Path -Parent $LogPath
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

function Write-Log {
    param([string]$Level, [string]$Message)
    Ensure-LogPath
    $timestamp = (Get-Date).ToString('s')
    $line = "$timestamp [$Level] $Message"
    Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
    $limitBytes = 5MB
    $fileInfo = Get-Item -LiteralPath $LogPath -ErrorAction SilentlyContinue
    if ($fileInfo -and $fileInfo.Length -gt $limitBytes) {
        $archived = "$LogPath.1"
        Move-Item -Force -LiteralPath $LogPath -Destination $archived
    }
}

function Decode-SsidBytes {
    param([byte[]]$Bytes)
    if (-not $Bytes) { return $null }
    return [System.Text.Encoding]::UTF8.GetString($Bytes).Trim([char]0)
}

function Get-WifiInterface {
    # NdisPhysicalMedium 9 = Native 802.11 (Wi-Fi)
    # Sort by Status (Up first), then by Name for deterministic selection with multiple adapters
    $wifi = Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
        Where-Object { $_.NdisPhysicalMedium -eq 9 } |
        Sort-Object -Property @{Expression={$_.Status}; Descending=$true}, @{Expression={$_.Name}; Ascending=$true} |
        Select-Object -First 1
    if (-not $wifi) { return $null }

    $ssid = $null
    $ssidInfo = Get-CimInstance -Namespace root/WMI -Class MSNdis_80211_ServiceSetIdentifier -ErrorAction SilentlyContinue |
        Where-Object { $_.Active -and $_.InstanceName -like "*$($wifi.InterfaceDescription)*" }
    if ($ssidInfo -and $ssidInfo.Ndis80211SsId) { $ssid = Decode-SsidBytes $ssidInfo.Ndis80211SsId }

    if (-not $ssid) {
        $lines = netsh wlan show interfaces 2>$null
        $ssidLine = $lines | Where-Object { $_ -match 'SSID' -and $_ -notmatch 'BSSID' } | Select-Object -First 1
        if ($ssidLine -match ':\s*(.+)$') { $ssid = $Matches[1] }
    }

    # Check if connection is metered (Windows 10+)
    $isMetered = $false
    try {
        # Check via WMI/CIM for actual metered status (Cost: 1=Unrestricted, 2+=Metered)
        $netCost = Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetConnectionCost -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceIndex -eq $wifi.ifIndex }
        if ($netCost -and $netCost.Cost -ge 2) { $isMetered = $true }
    } catch { }

    [pscustomobject]@{
        Name = $wifi.Name
        State = $wifi.Status
        SSID = $ssid
        InterfaceDescription = $wifi.InterfaceDescription
        IsMetered = $isMetered
    }
}

function Get-LastKnownSsidFromProfiles {
    # Try WMI first for locale-independent profile retrieval
    try {
        $wmiProfiles = Get-CimInstance -Namespace root/cimv2 -Class Win32_NetworkAdapterConfiguration -ErrorAction Stop |
            Where-Object { $_.IPEnabled -and $_.Description -match 'Wi-Fi|Wireless|802\.11' } |
            Select-Object -First 1
        # WMI doesn't directly expose WLAN profiles, fall through to netsh
    } catch { }

    # Fallback: parse netsh output (locale-dependent but with multiple pattern attempts)
    $lines = netsh wlan show profiles 2>$null
    foreach ($line in $lines) {
        # Try colon-based parsing (works for English and many locales)
        if ($line -match '^\s*[^:]+:\s*(.+)$') {
            $val = $Matches[1].Trim()
            # Skip lines that look like section headers, dashes, or empty
            if ($val -and $val -notmatch '^-+$' -and $val.Length -gt 0 -and $val -notmatch '^\s*$') {
                return $val
            }
        }
    }
    
    # Last resort: try XML export of profiles
    Write-Log "INFO" "Falling back to XML profile export for SSID detection (netsh parsing failed)"
    try {
        $tempDir = [System.IO.Path]::GetTempPath()
        $xmlPath = Join-Path $tempDir "wlan-profiles-temp"
        if (Test-Path $xmlPath) { Remove-Item -Recurse -Force $xmlPath }
        New-Item -ItemType Directory -Path $xmlPath -Force | Out-Null
        netsh wlan export profile folder="$xmlPath" 2>$null | Out-Null
        $xmlFiles = Get-ChildItem -Path $xmlPath -Filter "*.xml" -ErrorAction SilentlyContinue
        if ($xmlFiles) {
            $firstXml = $xmlFiles | Select-Object -First 1
            [xml]$profileXml = Get-Content -LiteralPath $firstXml.FullName -ErrorAction Stop
            $ssidName = $profileXml.WLANProfile.SSIDConfig.SSID.name
            Remove-Item -Recurse -Force $xmlPath -ErrorAction SilentlyContinue
            if ($ssidName) { return $ssidName }
        }
        Remove-Item -Recurse -Force $xmlPath -ErrorAction SilentlyContinue
    } catch { }
    
    return $null
}

function Get-TrafficSnapshot {
    param([string]$IfName)
    $stats = Get-NetAdapterStatistics -Name $IfName -ErrorAction SilentlyContinue
    if (-not $stats) { return $null }
    [pscustomobject]@{
        BytesRx = $stats.ReceivedBytes
        BytesTx = $stats.SentBytes
        Timestamp = Get-Date
    }
}

function Has-TrafficDelta {
    param($Prev, $Curr)
    if (-not $Prev -or -not $Curr) { return $false }
    $rx = $Curr.BytesRx - $Prev.BytesRx
    $tx = $Curr.BytesTx - $Prev.BytesTx
    return ($rx -gt 0 -or $tx -gt 0)
}

function Test-Connectivity {
    param(
        [string]$Target,
        [int]$Count = $script:PingCount,
        [int]$TimeoutMs = $script:PingTimeoutMs
    )
    # Use .NET Ping for cross-version compatibility (PS 5.1 lacks -TimeoutSeconds)
    $ping = New-Object System.Net.NetworkInformation.Ping
    try {
        for ($i = 0; $i -lt $Count; $i++) {
            try {
                $reply = $ping.Send($Target, $TimeoutMs)
                if ($reply.Status -eq 'Success') { return $true }
            } catch { }
        }
        return $false
    } finally {
        $ping.Dispose()
    }
}

function Ensure-WlanService {
    $svc = Get-Service WlanSvc -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Running') {
        Start-Service WlanSvc -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
}

function Get-DefaultGateway {
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Sort-Object -Property RouteMetric |
        Select-Object -First 1
    if ($route) { return $route.NextHop }
    return $null
}

function Test-VpnActive {
    # Check for active VPN connections that could affect ping reachability
    # RasPhone connections (built-in VPN)
    $rasConnections = Get-VpnConnection -ErrorAction SilentlyContinue | Where-Object { $_.ConnectionStatus -eq 'Connected' }
    if ($rasConnections) { return $true }
    
    # Check for common VPN adapter patterns (OpenVPN, WireGuard, etc.)
    $vpnAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -eq 'Up' -and (
            $_.InterfaceDescription -match 'TAP-Windows|OpenVPN|WireGuard|Cisco|Juniper|GlobalProtect|FortiClient|NordVPN|ExpressVPN|Cloudflare|WARP' -or
            $_.Name -match 'VPN|TAP|TUN|WireGuard'
        )
    }
    if ($vpnAdapters) { return $true }
    
    return $false
}

function Reset-WifiAdapter {
    param([string]$AdapterName)
    # Hard reset: disable then re-enable the Wi-Fi adapter (fixes wedged drivers)
    Write-Log "WARN" "Hard resetting Wi-Fi adapter: $AdapterName"
    try {
        Disable-NetAdapter -Name $AdapterName -Confirm:$false -ErrorAction Stop
        Start-Sleep -Seconds 3
        Enable-NetAdapter -Name $AdapterName -Confirm:$false -ErrorAction Stop
        Start-Sleep -Seconds 3
        # Ensure WLAN service is running after adapter reset
        $svc = Get-Service WlanSvc -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne 'Running') {
            Restart-Service WlanSvc -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        Start-Sleep -Seconds 2
        return $true
    } catch {
        Write-Log "ERROR" "Failed to reset adapter: $_"
        return $false
    }
}

function Get-BackoffSeconds {
    param([int]$ConsecutiveFailures, [int]$BaseSleep)
    # Exponential backoff: 10s -> 20s -> 40s -> 60s -> 120s -> 300s (capped at 5 min)
    if ($ConsecutiveFailures -lt 3) { return $BaseSleep }
    if ($ConsecutiveFailures -lt 6) { return [math]::Min(60, $BaseSleep * [math]::Pow(2, $ConsecutiveFailures - 3)) }
    if ($ConsecutiveFailures -lt 15) { return 60 }
    if ($ConsecutiveFailures -lt 30) { return 120 }
    return 300
}

function Test-JustResumedFromSleep {
    param([datetime]$LastIterationTime, [int]$ExpectedIntervalSeconds)
    $elapsed = ((Get-Date) - $LastIterationTime).TotalSeconds
    # If elapsed time is 5x expected, system likely slept (conservative to avoid false positives under load)
    return ($elapsed -gt ($ExpectedIntervalSeconds * 5))
}

function Get-AutoConnectProfiles {
    # Warn about multiple auto-connect profiles that could conflict
    $profiles = @()
    $lines = netsh wlan show profiles 2>$null
    foreach ($line in $lines) {
        if ($line -match '^\s*[^:]+:\s*(.+)$') {
            $val = $Matches[1].Trim()
            if ($val -and $val -notmatch '^-+$' -and $val.Length -gt 0) {
                $profiles += $val
            }
        }
    }
    return $profiles
}

function Test-WlanProfileExists {
    param([string]$ProfileName)
    # Validate that a WLAN profile exists before attempting to connect
    # Profile names usually match SSID but can differ if renamed
    $output = netsh wlan show profile name="$ProfileName" 2>&1
    return ($LASTEXITCODE -eq 0 -and $output -notmatch 'is not found|not found on the system')
}

# Store ping parameters at script scope for use in Test-Connectivity
$script:PingTimeoutMs = $PingTimeoutMs
$script:PingCount = $PingCount

Write-Log "INFO" "auto-wifi-recover version=$ScriptVersion hash=$ScriptHash starting; params SampleSeconds=$SampleSeconds MaxFailures=$MaxFailures CooldownSeconds=$CooldownSeconds MaxReconnectsPerHour=$MaxReconnectsPerHour PingTarget=$PingTarget PingTimeoutMs=$PingTimeoutMs PingCount=$PingCount LogPath=$LogPath"

# Initialize event log source if enabled
Initialize-EventLogSource
if ($EnableEventLog) {
    Write-EventLogEntry -Message "auto-wifi-recover v$ScriptVersion started" -EntryType Information -EventId 1000
}

Ensure-WlanService

$failureCount = 0
$prev = $null
$lastReconnect = (Get-Date).AddHours(-1)
$reconnectTimestamps = @()
$successChecks = 0
$failedChecks = 0
$targetSsid = $PreferredSsid
$captivePortalMode = $false
$captivePortalStart = $null
$consecutivePostReconnectFails = 0
$consecutiveTotalFailures = 0
$hardResetCooldownMinutes = 30
$lastHardReset = (Get-Date).AddHours(-1)
$lastIterationTime = Get-Date
$resumeGracePeriodEnd = $null
$cachedGateway = $null
$lastGatewayCheck = (Get-Date).AddMinutes(-5)
$gatewayCheckIntervalSeconds = 60  # Only re-resolve gateway every 60s unless forced

# Graceful shutdown handler
$script:isExiting = $false
$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    if (-not $script:isExiting) {
        $script:isExiting = $true
        Write-Log "INFO" "Script exiting (PowerShell.Exiting event)"
    }
}
trap {
    if (-not $script:isExiting) {
        $script:isExiting = $true
        Write-Log "ERROR" "Script terminated unexpectedly: $_"
    }
    break
}
# Ctrl+C handler for clean exit
try {
    [Console]::TreatControlCAsInput = $false
    $null = [Console]::CancelKeyPress.Add({
        param($sender, $e)
        $e.Cancel = $true
        if (-not $script:isExiting) {
            $script:isExiting = $true
            Write-Log "INFO" "Script stopped by user (Ctrl+C)"
            Write-Host "`n[info] Shutting down gracefully..." -ForegroundColor Gray
        }
        [Environment]::Exit(0)
    })
} catch {
    # Console events may not be available in all hosts (e.g., ISE)
    Write-Log "INFO" "Console.CancelKeyPress not available in this host; using default Ctrl+C behavior"
}

# Check for potential profile conflicts
$allProfiles = Get-AutoConnectProfiles
if ($allProfiles.Count -gt 3) {
    Write-Log "INFO" "Found $($allProfiles.Count) Wi-Fi profiles. If you have multiple profiles for the same network, ensure only one has auto-connect enabled."
}

if (-not $targetSsid) {
    $initial = Get-WifiInterface
    if ($initial -and $initial.SSID) { $targetSsid = $initial.SSID }
}
if (-not $targetSsid) { $targetSsid = Get-LastKnownSsidFromProfiles }
if (-not $targetSsid) {
    Write-Log "ERROR" "No target SSID available (not connected and no profiles). Exiting to avoid flapping."
    throw "No known SSID to connect. Set -PreferredSsid or ensure a saved profile exists."
}
# Validate that a profile exists for the target SSID (profile name usually matches SSID)
if (-not (Test-WlanProfileExists -ProfileName $targetSsid)) {
    Write-Log "WARN" "No WLAN profile found matching '$targetSsid'. Profile name may differ from SSID. Reconnects may fail."
    Write-Host "[warn] No profile named '$targetSsid' found. Ensure profile name matches SSID or use -PreferredSsid with exact profile name." -ForegroundColor Yellow
}
Write-Log "INFO" "Using target SSID=$targetSsid"

Write-Host "Monitoring Wi-Fi connectivity. Press Ctrl+C to stop."

while ($true) {
    # Detect sleep/resume: if time gap is much larger than expected, system likely slept
    if (Test-JustResumedFromSleep -LastIterationTime $lastIterationTime -ExpectedIntervalSeconds $SampleSeconds) {
        $resumeGracePeriodEnd = (Get-Date).AddSeconds($ResumeGraceSeconds)
        Write-Log "INFO" "System resume detected; entering ${ResumeGraceSeconds}s grace period"
        Write-Host "[info] System woke from sleep; waiting ${ResumeGraceSeconds}s for Wi-Fi to stabilize..." -ForegroundColor Gray
        # Reset failure counters on wake to avoid false positives
        $failureCount = 0
        $consecutiveTotalFailures = 0
        $consecutivePostReconnectFails = 0
    }
    $lastIterationTime = Get-Date

    # During grace period after resume, just monitor without taking action
    if ($resumeGracePeriodEnd -and (Get-Date) -lt $resumeGracePeriodEnd) {
        $remaining = [math]::Ceiling(($resumeGracePeriodEnd - (Get-Date)).TotalSeconds)
        Write-Host "[info] Grace period: ${remaining}s remaining..." -ForegroundColor Gray
        Start-Sleep -Seconds ([math]::Min($SampleSeconds, $remaining))
        continue
    }
    $resumeGracePeriodEnd = $null

    # Resolve ping target with caching (only re-check gateway periodically or after reconnect)
    $effectivePingTarget = $PingTarget
    if ($UseGatewayPing) {
        $now = Get-Date
        $shouldRefreshGateway = (-not $cachedGateway) -or ($now -gt $lastGatewayCheck.AddSeconds($gatewayCheckIntervalSeconds))
        if ($shouldRefreshGateway) {
            $gw = Get-DefaultGateway
            $lastGatewayCheck = $now
            if ($gw) {
                if ($gw -ne $cachedGateway) {
                    Write-Log "INFO" "Gateway changed: $cachedGateway -> $gw"
                    $cachedGateway = $gw
                }
            }
        }
        if ($cachedGateway) {
            $effectivePingTarget = $cachedGateway
        }
    }

    $iface = Get-WifiInterface
    if (-not $iface) {
        $consecutiveTotalFailures++
        $sleepTime = Get-BackoffSeconds -ConsecutiveFailures $consecutiveTotalFailures -BaseSleep $SampleSeconds
        Write-Host "[warn] No Wi-Fi interface detected. Retrying in ${sleepTime}s..." -ForegroundColor Yellow
        Write-Log "WARN" "No Wi-Fi interface detected (backoff: ${sleepTime}s)"
        Start-Sleep -Seconds $sleepTime
        continue
    }
    $isConnected = ($iface.State -eq 'Up' -and $iface.SSID)

    if (-not $isConnected) {
        $consecutiveTotalFailures++
        $sleepTime = Get-BackoffSeconds -ConsecutiveFailures $consecutiveTotalFailures -BaseSleep $SampleSeconds
        Write-Host "[warn] Interface not connected. Attempting reconnect to $targetSsid..." -ForegroundColor Yellow
        Write-Log "WARN" "Interface not connected; attempting reconnect to SSID=$targetSsid (backoff: ${sleepTime}s)"
        
        $connectedSsid = Connect-WithFallback -PrimarySsid $targetSsid -FallbackList $FallbackSsids -InterfaceName $iface.Name
        if ($connectedSsid) {
            if ($connectedSsid -ne $targetSsid) {
                Write-Log "INFO" "Connected to fallback SSID: $connectedSsid"
                Show-ToastNotification -Title "Wi-Fi Fallback" -Message "Connected to $connectedSsid (primary unavailable)" -Type Warning
                Write-EventLogEntry -Message "Connected to fallback SSID: $connectedSsid" -EntryType Warning -EventId 1002
            }
        }
        
        Start-Sleep -Seconds $sleepTime
        $failureCount = 0
        $prev = $null
        continue
    }

    $curr = Get-TrafficSnapshot -IfName $iface.Name
    $trafficOk = Has-TrafficDelta $prev $curr
    $pingOk = Test-Connectivity -Target $effectivePingTarget

    if ($pingOk) {
        $failureCount = 0
        $successChecks++
        $consecutivePostReconnectFails = 0
        $consecutiveTotalFailures = 0
        if ($captivePortalMode) {
            Write-Log "INFO" "Captive portal mode cleared; connectivity restored"
            $captivePortalMode = $false
            $captivePortalStart = $null
        }
        Write-Host "[ok] Connected to $($iface.SSID); ping OK." 
        if ($iface.SSID) {
            # Detect if Windows switched us to a different network (profile conflict)
            if ($iface.SSID -ne $targetSsid) {
                Write-Log "INFO" "SSID changed from $targetSsid to $($iface.SSID) (Windows may have auto-switched)"
                # Only update targetSsid if user didn't explicitly pin one with -PreferredSsid
                if (-not $PreferredSsid) {
                    $targetSsid = $iface.SSID
                }
            }
        }
    } else {
        $consecutiveTotalFailures++
        $failureCount++
        $failedChecks++
        $trafficNote = if ($trafficOk) { "local traffic seen" } else { "no traffic seen" }
        Write-Host "[warn] Ping failed ($failureCount/$MaxFailures); $trafficNote." -ForegroundColor Yellow
    }

    if ($failureCount -ge $MaxFailures) {
        # Skip reconnect if VPN is active (ping failure may be VPN routing, not Wi-Fi)
        if (Test-VpnActive) {
            Write-Host "[info] VPN detected; skipping reconnect (ping failure may be VPN-related)." -ForegroundColor Gray
            Write-Log "INFO" "Reconnect skipped: VPN connection active"
            $failureCount = 0
            Start-Sleep -Seconds $SampleSeconds
            continue
        }
        
        # Warn if on metered connection (reconnect will proceed but user should know)
        if ($iface.IsMetered) {
            Write-Log "INFO" "Reconnecting on metered connection"
        }
        
        # Skip reconnect if captive portal mode is active (reconnects won't help)
        if ($captivePortalMode) {
            $now = Get-Date
            $portalDuration = ($now - $captivePortalStart).TotalMinutes
            # If captive portal for 10+ min, try hard reset (but respect cooldown)
            if ($portalDuration -ge 10 -and $now -gt $lastHardReset.AddMinutes($hardResetCooldownMinutes)) {
                Write-Host "[action] Captive portal stuck for ${portalDuration} min; trying hard reset..." -ForegroundColor Red
                $resetOk = Reset-WifiAdapter -AdapterName $iface.Name
                $lastHardReset = $now
                if ($resetOk) {
                    $captivePortalMode = $false
                    $captivePortalStart = $null
                    $consecutivePostReconnectFails = 0
                    # Reconnect after reset with fallback support
                    Start-Sleep -Seconds 3
                    $connectedSsid = Connect-WithFallback -PrimarySsid $targetSsid -FallbackList $FallbackSsids -InterfaceName $iface.Name
                    if (-not $connectedSsid) {
                        Write-Log "ERROR" "netsh connect after hard reset failed for all SSIDs"
                    }
                }
            }
            $failureCount = 0
            $sleepTime = Get-BackoffSeconds -ConsecutiveFailures $consecutiveTotalFailures -BaseSleep $SampleSeconds
            Start-Sleep -Seconds $sleepTime
            continue
        }
        $now = Get-Date
        if ($now -lt $lastReconnect.AddSeconds($CooldownSeconds)) {
            Write-Log "INFO" "Reconnect skipped due to cooldown; SSID=$($iface.SSID)"
            $failureCount = 0
            Start-Sleep -Seconds $SampleSeconds
            continue
        }
        $reconnectTimestamps = $reconnectTimestamps | Where-Object { $_ -gt $now.AddHours(-1) }
        if ($reconnectTimestamps.Count -ge $MaxReconnectsPerHour) {
            Write-Log "WARN" "Reconnect skipped due to hourly cap; SSID=$($iface.SSID)"
            $failureCount = 0
            Start-Sleep -Seconds $SampleSeconds
            continue
        }
        Write-Host "[action] Reconnecting Wi-Fi ($targetSsid)..." -ForegroundColor Cyan
        Write-Log "INFO" "Reconnecting Wi-Fi; SSID=$targetSsid"
        $disconnectOutput = netsh wlan disconnect interface="$($iface.Name)" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "WARN" "netsh disconnect failed (exit=$LASTEXITCODE): $disconnectOutput"
        }
        Start-Sleep -Seconds 3
        
        $connectedSsid = Connect-WithFallback -PrimarySsid $targetSsid -FallbackList $FallbackSsids -InterfaceName $iface.Name
        $reconnectSuccess = $null -ne $connectedSsid
        
        if ($reconnectSuccess) {
            if ($connectedSsid -ne $targetSsid) {
                Write-Log "INFO" "Reconnected to fallback SSID: $connectedSsid"
                Show-ToastNotification -Title "Wi-Fi Fallback" -Message "Connected to $connectedSsid" -Type Warning
                Write-EventLogEntry -Message "Reconnected to fallback SSID: $connectedSsid" -EntryType Warning -EventId 1002
            } else {
                Show-ToastNotification -Title "Wi-Fi Reconnected" -Message "Restored connection to $connectedSsid" -Type Info
                Write-EventLogEntry -Message "Wi-Fi reconnected to $connectedSsid" -EntryType Information -EventId 1001
            }
        } else {
            Write-Log "ERROR" "All connection attempts failed (primary + fallbacks)"
            Show-ToastNotification -Title "Wi-Fi Failed" -Message "Could not connect to any network" -Type Error
            Write-EventLogEntry -Message "All Wi-Fi connection attempts failed" -EntryType Error -EventId 2001
        }
        $failureCount = 0
        $prev = $null
        $lastReconnect = $now
        $reconnectTimestamps += $now
        $consecutivePostReconnectFails = 0
        Start-Sleep -Seconds 5
        
        # Force gateway refresh after reconnect (IP may have changed)
        $postReconnectTarget = $PingTarget
        if ($UseGatewayPing) {
            $freshGateway = Get-DefaultGateway
            if ($freshGateway) {
                $cachedGateway = $freshGateway
                $lastGatewayCheck = Get-Date
                $postReconnectTarget = $freshGateway
            }
        }
        
        # Check if reconnect helped; if not, may be captive portal
        $postReconnectPing = Test-Connectivity -Target $postReconnectTarget
        if (-not $postReconnectPing) {
            $consecutivePostReconnectFails++
            if ($consecutivePostReconnectFails -ge 2 -and -not $captivePortalMode) {
                $captivePortalMode = $true
                $captivePortalStart = Get-Date
                Write-Log "WARN" "Captive portal suspected; reconnects not helping. Pausing reconnects until ping succeeds. Try logging in via browser."
                Write-Host "[warn] Captive portal detected? Reconnects paused. Log in via browser." -ForegroundColor Magenta
            }
        }
        continue
    }

    $prev = $curr
    if (($successChecks + $failedChecks) -gt 0 -and (($successChecks + $failedChecks) % 30 -eq 0)) {
        Write-Log "INFO" "Health: successChecks=$successChecks failedChecks=$failedChecks reconnects=$($reconnectTimestamps.Count) SSID=$($iface.SSID)"
    }
    Start-Sleep -Seconds $SampleSeconds
}