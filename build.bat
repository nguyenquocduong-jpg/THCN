@echo off
title Build LAN Monitor
cd /d "%~dp0"
echo Dang bien dich lan_monitor_web.exe...
g++ -std=c++17 -O2 lan_monitor_web.cpp -I".\WinDivert\include" -L".\WinDivert\x64" -lWinDivert -lws2_32 -liphlpapi -o lan_monitor_web.exe
if %ERRORLEVEL% NEQ 0 (
    echo [LOI] Bien dich lan_monitor_web.exe that bai!
) else (
    echo [THANH CONG] Da bien dich lan_monitor_web.exe
)

echo.
echo Dang bien dich analyze_capture.exe...
g++ -std=c++17 -O2 analyze_capture.cpp -I".\WinDivert\include" -L".\WinDivert\x64" -lWinDivert -lws2_32 -liphlpapi -o analyze_capture.exe
if %ERRORLEVEL% NEQ 0 (
    echo [LOI] Bien dich analyze_capture.exe that bai!
) else (
    echo [THANH CONG] Da bien dich analyze_capture.exe
)

echo.
pause
