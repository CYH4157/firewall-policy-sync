@echo off
chcp 65001 >nul
cd /d "%~dp0"
set SG_PAUSE=1
echo === 預覽模式（DRY-RUN）：只顯示會做什麼，不會真的呼叫 API ===
echo.
sg_firewall.exe --dry-run %*
