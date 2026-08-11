@echo off
chcp 65001 >nul
cd /d "%~dp0"
set SG_PAUSE=1
echo === 正式匯入：會實際呼叫 API，把 Excel 的規則建立到安全群組 ===
echo.
sg_firewall.exe %*
