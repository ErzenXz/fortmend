param(
  [ValidateSet('Install','Uninstall')]
  [string]$Action = 'Install',
  [string]$Binary = "$PSScriptRoot\aegis.exe",
  [string]$Config = "$env:ProgramData\Aegis\agent.json"
)

$ErrorActionPreference = 'Stop'
$serviceName = 'AegisAgent'
$installDir = Join-Path $env:ProgramFiles 'Aegis'
$installedBinary = Join-Path $installDir 'aegis.exe'

if ($Action -eq 'Uninstall') {
  if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $serviceName | Out-Null
  }
  Write-Host 'Aegis service removed. Configuration and quarantine data were preserved.'
  exit 0
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this installer from an elevated PowerShell session.'
}
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path $Config) | Out-Null
Copy-Item -Force $Binary $installedBinary
$command = ('"{0}" agent --config "{1}"' -f $installedBinary, $Config)
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
  Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
  sc.exe config $serviceName binPath= $command start= auto | Out-Null
} else {
  sc.exe create $serviceName binPath= $command start= auto DisplayName= 'Aegis endpoint protection agent' | Out-Null
}
sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
Start-Service -Name $serviceName
Write-Host 'Aegis agent service installed. Enroll the device before expecting telemetry.'
