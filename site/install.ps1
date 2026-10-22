param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$OnboardArgs
)

$ErrorActionPreference = 'Stop'
$repository = 'ErzenXz/fortmend'
$releaseBase = "https://github.com/$repository/releases/download/v0.2.0-preview.1"
$architecture = if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') { 'arm64' } else { 'amd64' }
$asset = "fortmend-windows-$architecture.exe"
$installDirectory = if ($env:FORTMEND_INSTALL_DIR) { $env:FORTMEND_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Fortmend\bin' }
$temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("fortmend-install-" + [guid]::NewGuid())

New-Item -ItemType Directory -Force -Path $temporaryDirectory, $installDirectory | Out-Null
try {
  $binary = Join-Path $temporaryDirectory $asset
  $checksums = Join-Path $temporaryDirectory 'SHA256SUMS'
  Invoke-WebRequest -UseBasicParsing "$releaseBase/$asset" -OutFile $binary
  Invoke-WebRequest -UseBasicParsing "$releaseBase/SHA256SUMS" -OutFile $checksums
  $expected = ((Get-Content $checksums) | Where-Object { $_ -match "\s$([regex]::Escape($asset))$" } | Select-Object -First 1).Split()[0]
  if (-not $expected) { throw "Release checksum for $asset is missing." }
  $actual = (Get-FileHash -Algorithm SHA256 $binary).Hash.ToLowerInvariant()
  if ($actual -ne $expected.ToLowerInvariant()) { throw 'Fortmend download checksum did not match.' }
  $destination = Join-Path $installDirectory 'fortmend.exe'
  Copy-Item -Force $binary $destination
  Write-Host "Installed Fortmend at $destination"
  & $destination onboard @OnboardArgs
} finally {
  Remove-Item -Recurse -Force $temporaryDirectory -ErrorAction SilentlyContinue
}
