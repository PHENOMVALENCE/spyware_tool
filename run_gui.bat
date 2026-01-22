@echo off
echo Starting Browser Credential Audit GUI...
echo.
python browser_credential_audit_gui.py
if errorlevel 1 (
    echo.
    echo Error: Failed to start GUI
    echo Make sure Python and dependencies are installed
    pause
)
