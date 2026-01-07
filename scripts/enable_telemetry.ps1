<#
enable_telemetry.ps1 (Admin)
One-time setup for useful Windows telemetry in a lab.

Enables:
- Security Event ID 4688 (Process Creation)
- Command line in 4688 (where supported)
- PowerShell ScriptBlock logging (useful for visibility in demos)

Note: Sysmon is still recommended for consistent command line + hashes.
#>
[CmdletBinding()] param()

function Require-Admin {
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator."
  }
}

try {
  Require-Admin
  Write-Host "Enabling Windows auditing + PowerShell logging..." -ForegroundColor Cyan

  auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null

  $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
  New-Item -Path $regPath -Force | Out-Null
  New-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -PropertyType DWord -Value 1 -Force | Out-Null

  $psPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
  New-Item -Path $psPath -Force | Out-Null
  New-ItemProperty -Path $psPath -Name "EnableScriptBlockLogging" -PropertyType DWord -Value 1 -Force | Out-Null

  Write-Host "Done. Reboot may be required for some settings." -ForegroundColor Green
} catch { Write-Error $_ }
