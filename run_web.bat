@echo off
title LAN Monitor Web
cd /d "%~dp0"
echo ===================================================
echo     LAN MONITOR - WINDIVERT EDITION (PORT 8080)
echo ===================================================
echo.
echo Dang khoi dong Web Dashboard tai http://localhost:8080 ...
echo [Luu y: Chuong trinh can quyen Administrator de khoi chay WinDivert]
echo.
lan_monitor_web.exe
pause
