@echo off
setlocal EnableExtensions
cd /d "%~dp0"

title xaloAC Bug Bounty Security Platform

echo.
echo  xaloAC Bug Bounty Security Platform
 echo Developer: x410m1s0
echo.

where node >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Node.js bulunamadi. Node.js 22 veya ustunu kurun.
  pause
  exit /b 1
)

for /f "tokens=1" %%V in ('node -p "process.versions.node.split('.')[0]"') do set NODE_MAJOR=%%V
if %NODE_MAJOR% LSS 22 (
  echo [ERROR] Node.js 22 veya ustu gerekli. Mevcut major surum: %NODE_MAJOR%
  pause
  exit /b 1
)

if not exist package-lock.json (
  echo [SETUP] package-lock.json olusturuluyor...
  call npm install --package-lock-only
  if errorlevel 1 goto :failed
)

if not exist node_modules\playwright (
  echo [SETUP] Node bagimliliklari kuruluyor...
  call npm install
  if errorlevel 1 goto :failed
)

if not exist "%LOCALAPPDATA%\ms-playwright" (
  echo [SETUP] Chromium kuruluyor...
  call npx playwright install chromium
  if errorlevel 1 goto :failed
)

call npm run check
if errorlevel 1 goto :failed

echo.
echo [READY] xaloAC http://127.0.0.1:4173 adresinde baslatiliyor...
echo [INFO] Durdurmak icin bu pencerede Ctrl+C kullanin.
echo.
start "xaloAC Browser" http://127.0.0.1:4173
call npm start
exit /b %errorlevel%

:failed
echo.
echo [ERROR] Kurulum veya baslatma basarisiz oldu.
pause
exit /b 1
