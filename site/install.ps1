param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$OnboardArgs
)

$ErrorActionPreference = 'Stop'
$repository = 'ErzenXz/aegis'
$releaseBase = "https://github.com/$repository/releases/latest/download"
$architecture = if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') { 'arm64' } else { 'amd64' }
$asset = "aegis_windows_$architecture.exe"
$installDirectory = if ($env:AEGIS_INSTALL_DIR) { $env:AEGIS_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Aegis\bin' }
$temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("aegis-install-" + [guid]::NewGuid())

New-Item -ItemType Directory -Force -Path $temporaryDirectory, $installDirectory | Out-Null
try {
  $binary = Join-Path $temporaryDirectory $asset
  $checksums = Join-Path $temporaryDirectory 'checksums.txt'
  Invoke-WebRequest -UseBasicParsing "$releaseBase/$asset" -OutFile $binary
  Invoke-WebRequest -UseBasicParsing "$releaseBase/checksums.txt" -OutFile $checksums
  $expected = ((Get-Content $checksums) | Where-Object { $_ -match "\s$([regex]::Escape($asset))$" } | Select-Object -First 1).Split()[0]
  if (-not $expected) { throw "Release checksum for $asset is missing." }
  $actual = (Get-FileHash -Algorithm SHA256 $binary).Hash.ToLowerInvariant()
  if ($actual -ne $expected.ToLowerInvariant()) { throw 'Aegis download checksum did not match.' }
  $destination = Join-Path $installDirectory 'aegis.exe'
  Copy-Item -Force $binary $destination
  Write-Host "Installed Aegis at $destination"
  & $destination onboard @OnboardArgs
} finally {
  Remove-Item -Recurse -Force $temporaryDirectory -ErrorAction SilentlyContinue
}
