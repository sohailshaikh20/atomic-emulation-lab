<#
collect_telemetry.ps1 (Admin recommended)
Exports logs into the evidence folder:
- System.evtx, Application.evtx
- Sysmon Operational (if present) -> sysmon.evtx
- Security 4688 (time-windowed) -> security_process_creation.xml (CLIXML)

Usage:
.\collect_telemetry.ps1 -EvidenceFolder "C:\evidence\<RUN_ID>"
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$EvidenceFolder,
  [int]$WindowMinutesBefore = 2,
  [int]$WindowMinutesAfter = 5
)

function Require-Admin {
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator (EVTX export requires it)."
  }
}

function Export-Channel([string]$channel, [string]$outPath) {
  if (Test-Path $outPath) { Remove-Item $outPath -Force -ErrorAction SilentlyContinue }
  wevtutil epl $channel $outPath | Out-Null
  Write-Host "Exported $channel -> $outPath"
}

try {
  Require-Admin
  if (!(Test-Path $EvidenceFolder)) { throw "Evidence folder not found: $EvidenceFolder" }

  $metaPath = Join-Path $EvidenceFolder "meta.json"
  $startUtc = (Get-Date).ToUniversalTime().AddMinutes(-$WindowMinutesBefore)
  $endUtc = (Get-Date).ToUniversalTime().AddMinutes($WindowMinutesAfter)

  if (Test-Path $metaPath) {
    $meta = Get-Content $metaPath -Raw | ConvertFrom-Json
    if ($meta.start_utc) { $startUtc = ([datetime]::Parse($meta.start_utc)).ToUniversalTime().AddMinutes(-$WindowMinutesBefore) }
    if ($meta.end_utc)   { $endUtc   = ([datetime]::Parse($meta.end_utc)).ToUniversalTime().AddMinutes($WindowMinutesAfter) }
  }

  Write-Host "Collecting telemetry into: $EvidenceFolder" -ForegroundColor Cyan
  Write-Host ("Time window (UTC): {0} → {1}" -f $startUtc.ToString("o"), $endUtc.ToString("o"))

  Export-Channel "System"      (Join-Path $EvidenceFolder "system.evtx")
  Export-Channel "Application" (Join-Path $EvidenceFolder "application.evtx")

  $sysmonChannel = "Microsoft-Windows-Sysmon/Operational"
  try {
    wevtutil gl $sysmonChannel | Out-Null
    Export-Channel $sysmonChannel (Join-Path $EvidenceFolder "sysmon.evtx")
  } catch {
    Write-Host "Sysmon channel not found — Sysmon not installed?" -ForegroundColor Yellow
  }

  try {
    $filter = @{ LogName="Security"; Id=4688; StartTime=$startUtc; EndTime=$endUtc }
    $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
    $outXml = Join-Path $EvidenceFolder "security_process_creation.xml"
    $events | Export-Clixml -Path $outXml
    Write-Host "Exported Security 4688 -> $outXml"
  } catch {
    Write-Host "Failed to export Security 4688: $($_.Exception.Message)" -ForegroundColor Yellow
  }

  Write-Host "Telemetry collection complete." -ForegroundColor Green
} catch { Write-Error $_ }
