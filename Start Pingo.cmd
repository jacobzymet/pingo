@echo off
setlocal
cd /d "%~dp0"
if exist "dist\Pingo\Pingo.exe" (
    start "" "dist\Pingo\Pingo.exe"
    exit /b
)
if not exist ".venv\Scripts\python.exe" (
    echo Setting up Pingo. Python 3.11 or newer is required.
    python -m venv .venv
    if errorlevel 1 goto failed
)
".venv\Scripts\python.exe" -c "import webview, pingo.desktop, pingo.handshake; from importlib.metadata import version; assert tuple(map(int, version('cryptography').split('.'))) >= (50, 0, 2); assert version('noiseprotocol') == '0.3.1'" >nul 2>nul
if errorlevel 1 (
    echo Installing or repairing desktop dependencies...
    ".venv\Scripts\python.exe" -m pip install --force-reinstall -e ".[gui]"
    if errorlevel 1 goto failed
)
".venv\Scripts\python.exe" -c "import webview, pingo.desktop, pingo.handshake" >nul 2>nul
if errorlevel 1 goto failed
start "" ".venv\Scripts\pythonw.exe" -m pingo.desktop
exit /b
:failed
echo Pingo could not start. Check the error above and try again.
pause
exit /b 1
