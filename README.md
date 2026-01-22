# Browser Credential Security Audit Tool

## Overview

A comprehensive security audit tool that demonstrates how modern "Infostealer" malware extracts saved passwords from Chromium-based browsers. Designed for **Blue Team training** and **security posture assessment**.

## ⚠️ Educational Use Only

This tool is intended for:
- Security awareness training
- Testing detection capabilities
- Understanding attack vectors
- Building defensive rules
- Security research and education

## Features

### 🔍 Core Functionality
- Extracts saved passwords from Chromium browsers
- Decrypts passwords using Windows DPAPI
- Supports multiple browsers (Chrome, Edge, Brave, Opera, Vivaldi)
- Structured output format
- Detailed logging and error handling

### 🖥️ Two Interfaces

#### 1. GUI Version (Recommended)
- **File**: `browser_credential_audit_gui.py`
- User-friendly graphical interface
- Real-time progress indicators
- Visual results table
- Export functionality
- **Run**: Double-click `run_gui.bat` or `python browser_credential_audit_gui.py`

#### 2. Command Line Version
- **File**: `browser_credential_audit.py`
- Scriptable and automatable
- Detailed console output
- Suitable for batch processing
- **Run**: `python browser_credential_audit.py`

## Quick Start

### Installation

1. **Install Python dependencies:**
   ```bash
   python -m pip install pycryptodome pypiwin32
   ```
   
   Or use the provided script:
   - Double-click `install_dependencies.bat`

### Running the Tool

#### GUI Version (Easiest)
```bash
# Option 1: Double-click
run_gui.bat

# Option 2: Command line
python browser_credential_audit_gui.py
```

#### Command Line Version
```bash
python browser_credential_audit.py
```

## Supported Browsers

- ✅ Google Chrome
- ✅ Microsoft Edge
- ✅ Brave Browser
- ✅ Opera
- ✅ Vivaldi

## Requirements

- **OS**: Windows (DPAPI is Windows-specific)
- **Python**: 3.7 or higher
- **Dependencies**: 
  - `pycryptodome` (for AES-GCM decryption)
  - `pypiwin32` (for Windows DPAPI)
- **Permissions**: Must run as the same Windows user who saved passwords

## Important Notes

### Before Running

1. **Close your browser completely**
   - The browser locks the Login Data file while running
   - Check Task Manager to ensure no browser processes are running

2. **Run as correct user**
   - Must be logged in as the Windows user who saved the passwords
   - DPAPI uses user credentials for decryption

3. **Windows only**
   - This tool uses Windows DPAPI (Data Protection API)
   - Linux/Mac versions would require different decryption methods

## How It Works

### Attack Chain

1. **Locate Browser Data**: Finds browser data directories
2. **Access Login Data**: Copies SQLite database with encrypted passwords
3. **Extract Master Key**: Reads encrypted master key from `Local State`
4. **Decrypt Master Key**: Uses Windows DPAPI to decrypt master key
5. **Decrypt Passwords**: Uses AES-GCM to decrypt individual passwords
6. **Display Results**: Shows extracted credentials

### Technical Details

- **Master Key**: Encrypted with Windows DPAPI, stored in `Local State` JSON
- **Password Encryption**: AES-256-GCM with version prefixes (v10/v11)
- **Database**: SQLite format, table name `logins`
- **Decryption**: Uses `win32crypt.CryptUnprotectData()` for DPAPI

## Blue Team Training

### Detection Opportunities

#### File System Monitoring
Monitor access to:
```
AppData\Local\Google\Chrome\User Data\Default\Login Data
AppData\Local\Microsoft\Edge\User Data\Default\Login Data
```

**Detection Rule:**
```
Event: File Access
Path: *\User Data\Default\Login Data
Process: NOT IN (chrome.exe, msedge.exe, brave.exe)
Action: ALERT HIGH SEVERITY
```

#### Process Behavior
- Python processes accessing browser data
- Scripts loading `sqlite3.dll`
- Unusual file copy operations
- `CryptUnprotectData` API calls from non-system processes

### Defensive Measures

1. **Use Password Managers**
   - Bitwarden, 1Password, LastPass
   - Passwords stored outside browser
   - Additional encryption layers

2. **Browser Security**
   - Enable sync encryption with passphrase
   - Use hardware security keys
   - Enable two-factor authentication

3. **System Hardening**
   - Least privilege principle
   - Application whitelisting
   - Monitor file access with EDR
   - Regular security audits

## File Structure

```
spyware/
├── browser_credential_audit.py      # Command-line version
├── browser_credential_audit_gui.py  # GUI version
├── run_gui.bat                      # Quick launcher for GUI
├── install_dependencies.bat          # Dependency installer
├── install_dependencies.ps1         # PowerShell installer
├── requirements.txt                 # Python dependencies
├── README.md                        # This file
├── README_AUDIT.md                  # Detailed audit documentation
├── GUI_README.md                    # GUI-specific documentation
└── QUICK_START.md                   # Quick start guide
```

## Troubleshooting

### "Login Data file not found"
- Browser may not have saved passwords
- Using a different browser profile
- Browser not installed

### "Cannot access Login Data file"
- **Browser is running** (most common)
- Close browser completely
- Check Task Manager
- Run as administrator

### "Failed to decrypt master key"
- Must run as same Windows user
- Corrupted Local State file
- Unsupported encryption method

### "Missing required library"
```bash
python -m pip install pycryptodome pypiwin32
```

## Output Example

### GUI Output
- Visual table with all credentials
- Real-time log output
- Export to file functionality

### Command Line Output
```
================================================================================
EXTRACTED CREDENTIALS - Chrome
================================================================================

URL                                               | Username                      | Password                   | Last Used            | Times Used
--------------------------------------------------------------------------------------------------------------------
https://accounts.google.com                       | user@example.com              | MyPassword123              | 2024-01-15 14:30:22  | 45
https://www.facebook.com                          | user@email.com                | SecurePass456             | 2024-01-14 10:15:33  | 12
```

## Legal and Ethical Use

- ✅ Security research and education
- ✅ Authorized penetration testing
- ✅ Blue team training
- ✅ Security awareness
- ❌ Unauthorized access to systems
- ❌ Theft of credentials
- ❌ Malicious use

## References

- [Chrome Password Storage](https://chromium.googlesource.com/chromium/src/+/master/docs/security/faq.md)
- [DPAPI Documentation](https://docs.microsoft.com/en-us/windows/win32/api/dpapi/)
- [AES-GCM Specification](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)

## License

Educational use only. See LICENSE file for details.

## Disclaimer

This tool is provided for educational purposes only. The authors are not responsible for any misuse. Always obtain proper authorization before testing on systems you don't own.
