# Auto Wi-Fi Recover

A robust PowerShell script that monitors Wi-Fi connectivity and automatically reconnects when the connection drops. Designed for Windows 11 with intelligent handling of edge cases like captive portals, VPNs, sleep/resume cycles, and metered connections.

## Features

- **Automatic Reconnection** — Detects connectivity loss via ping and reconnects to your preferred network
- **Multi-SSID Fallback** — Ordered list of backup networks if primary is unavailable
- **Captive Portal Detection** — Pauses reconnects when login page is required (hotels, cafes)
- **VPN Awareness** — Skips reconnects when VPN is active to avoid false positives
- **Sleep/Resume Handling** — Grace period after wake to let Wi-Fi stabilize naturally
- **Rate Limiting** — Cooldown + hourly cap prevents reconnect storms
- **Exponential Backoff** — Scales wait times (10s → 5min) during persistent failures
- **Metered Connection Logging** — Tracks when reconnects occur on metered networks
- **Hard Reset Fallback** — Disables/re-enables adapter if soft reconnect fails repeatedly
- **Toast Notifications** — Optional Windows notifications on reconnect events
- **Windows Event Log** — Optional integration for enterprise monitoring
- **Scheduled Task Install** — One-command setup to run at logon

## Requirements

- Windows 10/11
- PowerShell 5.1+
- WLAN service running
- At least one saved Wi-Fi profile
- Administrator privileges (auto-elevates)

## Quick Start

```powershell
# Run interactively (auto-elevates to admin)
.\auto-wifi-recover.ps1

# Install as scheduled task (runs at logon, hidden)
.\auto-wifi-recover.ps1 -Install

# Uninstall scheduled task
.\auto-wifi-recover.ps1 -Uninstall
```

## Parameters

| Parameter                 | Default                                                         | Description                                             |
| ------------------------- | --------------------------------------------------------------- | ------------------------------------------------------- |
| `-SampleSeconds`        | `10`                                                          | Polling interval between connectivity checks            |
| `-MaxFailures`          | `3`                                                           | Failed pings before triggering reconnect                |
| `-PingTarget`           | `1.1.1.1`                                                     | IP to ping for connectivity test                        |
| `-PingTimeoutMs`        | `2000`                                                        | Ping timeout in milliseconds                            |
| `-PingCount`            | `2`                                                           | Ping attempts per check                                 |
| `-CooldownSeconds`      | `120`                                                         | Minimum gap between reconnects                          |
| `-MaxReconnectsPerHour` | `10`                                                          | Rate limit for reconnect attempts                       |
| `-PreferredSsid`        | *(auto)*                                                      | Pin to specific SSID (won't follow Windows auto-switch) |
| `-FallbackSsids`        | `@()`                                                         | Ordered backup SSIDs:`"Net1","Net2"`                  |
| `-UseGatewayPing`       | `$false`                                                      | Ping gateway instead of internet (for captive portals)  |
| `-ResumeGraceSeconds`   | `30`                                                          | Wait time after wake-from-sleep                         |
| `-EnableToast`          | `$false`                                                      | Show Windows toast notifications                        |
| `-EnableEventLog`       | `$false`                                                      | Write to Windows Event Log                              |
| `-LogPath`              | `C:\ProgramData\auto-wifi-recover\logs\auto-wifi-recover.log` | Log file location                                       |

## Usage Examples

### Basic monitoring

```powershell
.\auto-wifi-recover.ps1
```

### Pin to specific network with fallbacks

```powershell
.\auto-wifi-recover.ps1 -PreferredSsid "MyHomeWiFi" -FallbackSsids "MyHomeWiFi_5G","Backup_Network"
```

### Hotel/captive portal mode

```powershell
.\auto-wifi-recover.ps1 -UseGatewayPing -ResumeGraceSeconds 60
```

### High-latency network (satellite, weak signal)

```powershell
.\auto-wifi-recover.ps1 -PingTimeoutMs 5000 -PingCount 3 -MaxFailures 5
```

### Enterprise deployment with full logging

```powershell
.\auto-wifi-recover.ps1 -EnableEventLog -EnableToast -PreferredSsid "CorpWiFi" -Install
```

## How It Works

1. **Monitors** connectivity by pinging target every N seconds
2. **Counts** consecutive failures (traffic stats provide secondary signal)
3. **Reconnects** via `netsh wlan` when threshold reached (respecting cooldown/caps)
4. **Detects** captive portals if reconnects don't restore ping
5. **Falls back** to secondary SSIDs if primary unavailable
6. **Hard resets** adapter after prolonged captive portal state
7. **Logs** all events with automatic 5MB rotation

## Log Location

```
C:\ProgramData\auto-wifi-recover\logs\auto-wifi-recover.log
```

Logs rotate automatically at 5MB (archived to `.log.1`).

## Troubleshooting

| Issue                       | Solution                                                   |
| --------------------------- | ---------------------------------------------------------- |
| "No known SSID to connect"  | Connect to Wi-Fi manually first, or use `-PreferredSsid` |
| Reconnects too often        | Increase `-MaxFailures` or `-CooldownSeconds`          |
| Captive portal not detected | Use `-UseGatewayPing` flag                               |
| VPN breaks connectivity     | Script auto-detects most VPNs; ping failure is ignored     |
| Multiple adapters           | Script picks first "Up" adapter alphabetically by name     |
| Wrong network selected      | Use `-PreferredSsid` to pin specific network             |

## Security Notes

- Runs with admin privileges (required for `netsh` and adapter control)
- Logs stored in `C:\ProgramData` (admin-writeable)
- Scheduled task runs as current user with highest privileges
- Script hash logged at startup for integrity verification

## Limitations

- Windows only (uses `netsh wlan`, Windows Event Log, etc.)
- Requires saved Wi-Fi profile (won't connect to new networks)
- Profile name must match SSID (or specify exact profile name)
- Toast notifications require BurntToast module for rich notifications (falls back to balloon tips)

## Version

**1.8.0** — December 2025

## Roadmap

> **Note:** This PowerShell implementation will be rewritten in **C#** for improved performance, better service integration, and cross-platform potential via .NET. The C# version will feature:
>
> - Native Windows Service support (no scheduled task workaround)
> - Lower resource footprint
> - Proper async/await for non-blocking operations
> - WinRT APIs for modern Wi-Fi management
> - MAUI/WPF tray application option
> - Configuration via JSON/YAML

## License

MIT — Use freely, attribution appreciated.

---

*Made for unreliable Wi-Fi everywhere.*
