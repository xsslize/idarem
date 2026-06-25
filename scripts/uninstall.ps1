# Removes the idarem loader from IDA's user plugins folder.
#   Usage:  powershell -ExecutionPolicy Bypass -File scripts\uninstall.ps1

$ErrorActionPreference = "Stop"

function Get-IdaUserDir {
    if ($env:IDAUSR) { return ($env:IDAUSR -split ';')[0] }
    return (Join-Path $env:APPDATA "Hex-Rays\IDA Pro")
}

$LoaderPath = Join-Path (Get-IdaUserDir) "plugins\idarem.py"
if (Test-Path $LoaderPath) {
    Remove-Item $LoaderPath
    Write-Host "Removed $LoaderPath" -ForegroundColor Green
}
else {
    Write-Host "Nothing to remove ($LoaderPath not found)." -ForegroundColor Yellow
}
