@echo off
echo ========================================
echo Installing Browser Credential Audit Dependencies
echo ========================================
echo.

echo [1/3] Installing pycryptodome...
python -m pip install pycryptodome

echo.
echo [2/3] Installing pypiwin32...
python -m pip install pypiwin32

echo.
echo [3/3] Running pywin32 post-install...
python -m pywin32_postinstall -install

echo.
echo ========================================
echo Installation Complete!
echo ========================================
echo.
echo You can now run: python browser_credential_audit.py
echo.
pause
