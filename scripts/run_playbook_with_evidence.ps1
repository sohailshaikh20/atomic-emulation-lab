<#
run_playbook_with_evidence.ps1
Runs an Atomic Red Team test and creates an auditable evidence package.

Outputs:
- meta.json
- command.txt
- atomic_output.log
- process-list.csv (best-effort)
- manifest.sha256

Usage:
.\run_playbook_with_evidence.ps1 -PlaybookID "RT-ATOMIC-PORTFOLIO" -TechniqueId "T1016" -TestNumbers "1" -PathToAtomicsFolder "C:\AtomicRedTeam\atomics" -Operator "md_sohail" [-Simulate]
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$PlaybookID,
  [Parameter(Mandatory=$true)][string]$TechniqueId,
  [Parameter(Mandatory=$true)][string]$TestNumbers,
  [Parameter(Mandatory=$true)][string]$PathToAtomicsFolder,
  [Parameter(Mandatory=$true)][string]$Operator,
  [switch]$Simulate,
  [string]$EvidenceRoot = "C:\evidence"
)

function Ensure-Dir([string]$p) { if (!(Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null } }

function New-RunId([string]$prefix) {
  $ts = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmss")
  return "${prefix}_RUN_${ts}"
}

function Write-ManifestSha256([string]$folder) {
  $out = Join-Path $folder "manifest.sha256"
  $files = Get-ChildItem -Path $folder -File -Recurse | Where-Object { $_.Name -ne "manifest.sha256" }
  $lines = foreach ($f in $files) {
    try {
      $h = Get-FileHash -Path $f.FullName -Algorithm SHA256
      $rel = $f.FullName.Substring($folder.Length).TrimStart("\")
      "{0}  {1}" -f $h.Hash.ToLower(), $rel
    } catch { }
  }
  $lines | Out-File -FilePath $out -Encoding utf8
}

try {
  Ensure-Dir $EvidenceRoot
  $runId = New-RunId $PlaybookID
  $evidenceFolder = Join-Path $EvidenceRoot $runId
  Ensure-Dir $evidenceFolder

  $startUtc = (Get-Date).ToUniversalTime().ToString("o")
  Write-Host "=== Starting playbook run: $runId ===" -ForegroundColor Cyan

  $meta = [ordered]@{
    run_id = $runId
    playbook_id = $PlaybookID
    technique_id = $TechniqueId
    test_numbers = $TestNumbers
    operator = $Operator
    start_utc = $startUtc
    path_to_atomics_folder = $PathToAtomicsFolder
    simulate = [bool]$Simulate
  }
  ($meta | ConvertTo-Json -Depth 6) | Out-File (Join-Path $evidenceFolder "meta.json") -Encoding utf8

  $cmd = "Invoke-AtomicTest -AtomicTechnique $TechniqueId -TestNumbers $TestNumbers -PathToAtomicsFolder `"$PathToAtomicsFolder`" -Confirm:`$false"
  $cmd | Out-File (Join-Path $evidenceFolder "command.txt") -Encoding utf8

  $logPath = Join-Path $evidenceFolder "atomic_output.log"

  if ($Simulate) {
    "SIMULATED: technique=$TechniqueId test=$TestNumbers run_id=$runId operator=$Operator start_utc=$startUtc" | Out-File $logPath -Encoding utf8
    "SIMULATION COMPLETE" | Add-Content $logPath
  } else {
    if (-not (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue)) {
      throw "Invoke-AtomicTest not found. Install Invoke-AtomicRedTeam and verify it loads."
    }
    "Executing: $cmd" | Out-File $logPath -Encoding utf8
    $out = Invoke-AtomicTest -AtomicTechnique $TechniqueId -TestNumbers $TestNumbers -PathToAtomicsFolder $PathToAtomicsFolder -Confirm:$false 2>&1 | Out-String
    $out | Add-Content $logPath
  }

  $meta.end_utc = (Get-Date).ToUniversalTime().ToString("o")
  ($meta | ConvertTo-Json -Depth 6) | Out-File (Join-Path $evidenceFolder "meta.json") -Encoding utf8

  try {
    Get-Process | Select-Object Name,Id,Path,StartTime | Export-Csv -NoTypeInformation -Path (Join-Path $evidenceFolder "process-list.csv") -Encoding UTF8
  } catch { }

  Write-ManifestSha256 $evidenceFolder

  Write-Host "`n=== Playbook run complete ===" -ForegroundColor Green
  Write-Host "Evidence directory: $evidenceFolder"
  Write-Host "Next: .\collect_telemetry.ps1 -EvidenceFolder `"$evidenceFolder`""
} catch { Write-Error $_ }
