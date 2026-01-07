<#
analyze_evidence.ps1
Best-effort local analysis (not a substitute for SIEM/EDR):
- Reads meta.json for technique + time window
- Searches evidence logs for technique keywords
- Writes detection_summary.json

Usage:
.\analyze_evidence.ps1 -EvidenceFolder "C:\evidence\<RUN_ID>"
#>

[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$EvidenceFolder)

function TryParseUtc([string]$s){ try { ([datetime]::Parse($s)).ToUniversalTime() } catch { $null } }

try {
  if (!(Test-Path $EvidenceFolder)) { throw "Evidence folder not found: $EvidenceFolder" }

  Write-Host "Analyzing evidence folder: $EvidenceFolder" -ForegroundColor Cyan
  $metaPath = Join-Path $EvidenceFolder "meta.json"
  if (!(Test-Path $metaPath)) { throw "meta.json not found." }
  $meta = Get-Content $metaPath -Raw | ConvertFrom-Json

  $runId = $meta.run_id
  $techniqueId = $meta.technique_id
  $operator = $meta.operator
  $startUtc = TryParseUtc $meta.start_utc
  $endUtc = TryParseUtc $meta.end_utc
  if (-not $startUtc) { $startUtc = (Get-Date).ToUniversalTime().AddMinutes(-5) }
  if (-not $endUtc)   { $endUtc   = $startUtc.AddMinutes(10) }

  Write-Host "RUN_ID: $runId"
  Write-Host "Technique: $techniqueId"
  Write-Host "Operator: $operator"
  Write-Host "Start (UTC): $($startUtc.ToString('o'))"

  $keywords = @($runId, $operator, $techniqueId, "Invoke-Atomic", "Invoke-AtomicTest", "PowerShell")
  switch -Regex ($techniqueId) {
    "^T1016" { $keywords += @("ipconfig","netstat","route","Network Configuration") }
    "^T1082" { $keywords += @("systeminfo","wmic","ComputerSystem") }
    "^T1083" { $keywords += @("dir ","Get-ChildItem","tree ","File and Directory") }
    "^T1057" { $keywords += @("tasklist","Get-Process") }
    "^T1033" { $keywords += @("whoami","query user") }
  }

  Write-Host ("Search keywords: " + ($keywords -join ", "))

  $found = New-Object System.Collections.Generic.List[object]
  $times = New-Object System.Collections.Generic.List[datetime]

  $atomicLog = Join-Path $EvidenceFolder "atomic_output.log"
  if (Test-Path $atomicLog) {
    Write-Host "Scanning atomic_output.log..."
    $txt = Get-Content $atomicLog -Raw -ErrorAction SilentlyContinue
    foreach ($k in $keywords) {
      if ($k -and $txt -match [regex]::Escape($k)) { $found.Add(@{source="atomic_output.log"; detail="keyword match: $k"}) | Out-Null; break }
    }
  }

  $cmd = Join-Path $EvidenceFolder "command.txt"
  if (Test-Path $cmd) { Write-Host "Scanning command.txt..."; $found.Add(@{source="command.txt"; detail="command recorded"}) | Out-Null }

  $evtxFiles = Get-ChildItem -Path $EvidenceFolder -Filter *.evtx -File -ErrorAction SilentlyContinue
  foreach ($evtx in $evtxFiles) {
    Write-Host "Searching EVTX: $($evtx.Name)"
    try {
      $filter = @{ Path=$evtx.FullName; StartTime=$startUtc.AddMinutes(-2); EndTime=$endUtc.AddMinutes(5) }
      $events = $null
      try { $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop }
      catch { $events = Get-WinEvent -Path $evtx.FullName -MaxEvents 3000 -ErrorAction Stop }

      foreach ($k in $keywords) {
        if (-not $k) { continue }
        $m = $events | Where-Object { $_.Message -and ($_.Message -match [regex]::Escape($k)) } | Select-Object -First 1
        if ($m) {
          $t = $m.TimeCreated.ToUniversalTime()
          $found.Add(@{source=$evtx.Name; detail="EVTX keyword match: $k (eventid: $($m.Id))"; time=$t.ToString("o")}) | Out-Null
          $times.Add($t) | Out-Null
          break
        }
      }
    } catch {
      Write-Host "  Could not read EVTX $($evtx.Name): $($_.Exception.Message)" -ForegroundColor Yellow
    }
  }

  $detected = $false
  $first = $null
  if ($times.Count -gt 0) { $detected = $true; $first = ($times | Sort-Object)[0] }
  elseif ($found.Count -gt 0) { $detected = $true }

  $ttd = $null
  if ($first) { $ttd = [int](($first - $startUtc).TotalSeconds) }

  $summary = [ordered]@{
    run_id=$runId
    playbook_id=$meta.playbook_id
    technique_id=$techniqueId
    operator=$operator
    evidence_folder=$EvidenceFolder
    start_utc=$startUtc.ToString("o")
    detected=$detected
    detection_timestamp= if($first){$first.ToString("o")} else {$null}
    time_to_detect_seconds=$ttd
    detection_sources=$found
    note="Best-effort local analysis. Use SIEM/EDR for authoritative detection maturity scoring."
  }

  $outPath = Join-Path $EvidenceFolder "detection_summary.json"
  ($summary | ConvertTo-Json -Depth 8) | Out-File $outPath -Encoding utf8

  Write-Host "`n==== Detection Summary ====" -ForegroundColor Green
  Write-Host "Detected: $detected"
  if ($first) { Write-Host "Detection timestamp (UTC): $($first.ToString('o'))"; Write-Host "Time to detect (s): $ttd" }
  Write-Host "Detailed sources found:"
  $found | ForEach-Object { Write-Host (" - {0}: {1}" -f $_.source, $_.detail) }
  Write-Host "`nA JSON summary was written to: $outPath" -ForegroundColor Cyan

} catch { Write-Error $_ }
