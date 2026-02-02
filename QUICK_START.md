# Quick Start Guide

## Installation Complete! ✅

The required dependencies have been installed:
- ✅ pycryptodome
- ✅ pypiwin32 (includes pywin32)

## How to Run

### 🖥️ GUI Version (Recommended for Beginners)

**Easiest way:**
1. Double-click `run_gui.bat`
2. Select your browser from the dropdown
3. Click "Run Audit"
4. View results in the table

**Or run directly:**
```cmd
python browser_credential_audit_gui.py
```

### 💻 Command Line Version

**Option 1: Double-click the script**
Simply double-click `browser_credential_audit.py` in Windows Explorer

**Option 2: Command Prompt**
```cmd
cd C:\xampp\htdocs\spyware
python browser_credential_audit.py
```

**Option 3: PowerShell**
```powershell
cd C:\xampp\htdocs\spyware
python browser_credential_audit.py
```

## Important Notes

1. **Close your browser first** - The browser locks the Login Data file while running
2. **Run as the same user** - You must be logged in as the user who saved the passwords
3. **Windows only** - This script uses Windows DPAPI (Data Protection API)

## Troubleshooting

### If you get "Login Data file not found"
- Make sure you have saved passwords in your browser
- Check that you selected the correct browser
- Browser might be using a different profile

### If you get "Cannot access Login Data file"
- **Close the browser completely** (check Task Manager)
- Try running as administrator
- Make sure no other processes are accessing the file

### If you get "Failed to decrypt master key"
- You must run as the same Windows user who saved the passwords
- Check that Local State file exists and is readable

## Block the simulator: Browser Data Guard

To **block** the simulator from reading Chrome/Edge passwords and history:

**Option 1 – GUI (easiest)**  
1. Close Chrome and Edge (and for Edge: end **msedgewebview2.exe** in Task Manager if needed).  
2. Double-click **`run_guard_gui.bat`** (or run `python browser_data_guard_gui.py`).  
3. Click **Start protection**. The simulator is now blocked.  
4. Click **Stop protection** when you want to use the browser again.

**Option 2 – Console**  
1. Close Chrome/Edge completely (check Task Manager).  
2. Double-click **`run_guard.bat`** or run `python browser_data_guard.py`.  
3. Keep the window open while you want protection.  
4. Press **Ctrl+C** to stop and release the files.

**Note:** While protection is on, the browser cannot start (files are locked). Stop the guard when you want to browse again.

## Next Steps

1. Run the script and select your browser
2. Review the extracted credentials (if any)
3. Use this for Blue Team training exercises
4. Test your detection capabilities

## Installation Scripts

If you need to reinstall dependencies:
- **Windows Batch**: Double-click `install_dependencies.bat`
- **PowerShell**: Right-click `install_dependencies.ps1` → Run with PowerShell

Or manually:
```cmd
python -m pip install pycryptodome pypiwin32
```
