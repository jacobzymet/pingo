param([string]$Python = '')

$ErrorActionPreference = 'Stop'
$pingoRoot = Split-Path -Parent $PSScriptRoot
$pingoPython = if ($Python) { (Resolve-Path -LiteralPath $Python).Path } else { Join-Path $pingoRoot '.venv\Scripts\python.exe' }
if (-not (Test-Path -LiteralPath $pingoPython)) {
    throw 'Create .venv with Python 3.11 or newer first: python -m venv .venv'
}
Push-Location $pingoRoot
try {
    & $pingoPython -c "import sys; minimum = {(3, 11): 17, (3, 12): 15, (3, 13): 16, (3, 14): 8}; v = sys.version_info; assert v[:2] in minimum and v.micro >= minimum[v[:2]] or v[:2] >= (3, 15), 'Use a patched Python runtime (3.13.16 or 3.14.8 recommended).'; assert sys.maxsize > 2**32, 'Use 64-bit Python.'"
    if ($LASTEXITCODE -ne 0) { throw 'Unsupported release-build runtime. Pass -Python PATH to a maintained 64-bit environment.' }
    & $pingoPython -m pip install --upgrade 'pip>=26.2'
    if ($LASTEXITCODE -ne 0) { throw 'Build tool installation failed.' }
    & $pingoPython -m pip install -e '.[build]'
    if ($LASTEXITCODE -ne 0) { throw 'Desktop dependency installation failed.' }
    & $pingoPython -m PyInstaller --noconfirm 'packaging/pingo.spec'
    if ($LASTEXITCODE -ne 0) { throw 'Desktop build failed.' }
    Copy-Item -LiteralPath 'README.md' -Destination 'dist/Pingo/README.md'
    Copy-Item -LiteralPath 'LICENSE' -Destination 'dist/Pingo/LICENSE'
    Copy-Item -LiteralPath 'NOTICE' -Destination 'dist/Pingo/NOTICE'
    New-Item -ItemType Directory -Path 'dist/Pingo/licenses' -Force | Out-Null
    Copy-Item -Path 'dist/Pingo/_internal/licenses/*' -Destination 'dist/Pingo/licenses' -Recurse -Force
    Compress-Archive -LiteralPath 'dist/Pingo' -DestinationPath 'dist/Pingo-Windows.zip' -Force
    Write-Output 'Built dist/Pingo/Pingo.exe. Distribute the whole Pingo folder.'
    Write-Output 'Portable package: dist/Pingo-Windows.zip'
} finally {
    Pop-Location
}
