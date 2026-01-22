Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Installing Browser Credential Audit Dependencies" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1/3] Installing pycryptodome..." -ForegroundColor Yellow
python -m pip install pycryptodome

Write-Host ""
Write-Host "[2/3] Installing pypiwin32..." -ForegroundColor Yellow
python -m pip install pypiwin32

Write-Host ""
Write-Host "[3/3] Running pywin32 post-install..." -ForegroundColor Yellow
python -m pywin32_postinstall -install

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Installation Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "You can now run: python browser_credential_audit.py" -ForegroundColor Cyan
Write-Host ""
