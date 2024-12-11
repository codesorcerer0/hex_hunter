@echo off
:start
py HEX_HUNTER.py
if %errorlevel% neq 0 (
    echo Script crashed. Restarting...
    timeout /t 2
    goto start
)