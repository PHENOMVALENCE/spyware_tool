# Browser Credential Security Audit Tool

## Overview

This Python script demonstrates how modern "Infostealer" malware extracts saved passwords from Chromium-based browsers. It's designed for **Blue Team training** and **security posture assessment**.

## ⚠️ Educational Use Only

This tool is intended for:
- Security awareness training
- Testing detection capabilities
- Understanding attack vectors
- Building defensive rules
- Security research and education

**DO NOT use this tool for unauthorized access to systems or data.**

## How It Works

### Attack Chain

1. **Locate Browser Data**: Finds browser data directories (Chrome, Edge, Brave, etc.)
2. **Access Login Data**: Copies the SQLite database containing encrypted passwords
3. **Extract Master Key**: Reads encrypted master key from `Local State` file
4. **Decrypt Master Key**: Uses Windows DPAPI to decrypt the master key
5. **Decrypt Passwords**: Uses AES-GCM to decrypt individual passwords
6. **Display Results**: Shows extracted credentials in structured format

### Technical Details

#### Master Key Extraction
- Chrome stores an encrypted master key in `Local State` (JSON file)
- The key is encrypted using Windows DPAPI (Data Protection API)
- DPAPI uses the current user's Windows credentials automatically
- We use `win32crypt.CryptUnprotectData()` to decrypt it

#### Password Decryption
- Passwords are encrypted using AES-256-GCM
- Each password has a version prefix (`v10` or `v11`)
- 12-byte IV (Initialization Vector) for GCM mode
- Encrypted password + authentication tag

#### Database Structure
- SQLite database: `Login Data`
- Table: `logins`
- Fields: `origin_url`, `username_value`, `password_value`, timestamps

## Installation

### Prerequisites
- Python 3.7+
- Windows OS (DPAPI is Windows-specific)
- Chromium-based browser with saved passwords

### Install Dependencies

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install pycryptodome pypiwin32
```

## Usage

### Basic Usage

```bash
python browser_credential_audit.py
```

The script will:
1. List available browsers
2. Prompt for browser selection
3. Perform the audit
4. Display results in a structured table

### Supported Browsers

- Google Chrome
- Microsoft Edge
- Brave Browser
- Opera
- Vivaldi

## Output Example

```
================================================================================
EXTRACTED CREDENTIALS - Chrome
================================================================================

URL                                               | Username                      | Password                   | Last Used            | Times Used
--------------------------------------------------------------------------------------------------------------------
https://accounts.google.com                       | user@example.com              | MyPassword123              | 2024-01-15 14:30:22  | 45
https://www.facebook.com                          | user@email.com                | SecurePass456             | 2024-01-14 10:15:33  | 12
...
```

## Blue Team Training

### Detection Opportunities

#### 1. File System Access Monitoring
Monitor access to browser data directories:
- `AppData\Local\Google\Chrome\User Data\Default\Login Data`
- `AppData\Local\Microsoft\Edge\User Data\Default\Login Data`

**Detection Rule:**
```
Event: File Access
Path: *\User Data\Default\Login Data
Process: NOT IN (chrome.exe, msedge.exe, brave.exe)
Action: ALERT HIGH SEVERITY
```

#### 2. Process Behavior Analysis
Look for:
- Python processes accessing browser data directories
- Scripts loading `sqlite3.dll`
- Unusual file copy operations in browser directories
- Processes calling `CryptUnprotectData` API

#### 3. Using Process Monitor (Sysinternals)

1. Open Process Monitor
2. Set filters:
   - Process Name: `python.exe` (or your script name)
   - Path: Contains `Login Data`
3. Run the audit script
4. Observe file system events

You'll see:
- File reads on `Login Data`
- File reads on `Local State`
- File copy operations

### Defensive Measures

#### 1. Use Password Managers
- **Bitwarden**, **1Password**, **LastPass**, etc.
- Passwords stored outside browser
- Additional encryption layers
- Master password protection

#### 2. Browser Security Settings
- Enable browser sync encryption with passphrase
- Use hardware security keys
- Enable two-factor authentication
- Regularly clear saved passwords

#### 3. System Hardening
- Least privilege principle
- Application whitelisting
- Monitor file access with EDR solutions
- Regular security audits

#### 4. Detection Implementation

**SIEM Query Example (Splunk):**
```
index=windows EventCode=4656 ObjectName="*Login Data*" 
| where ProcessName != "chrome.exe" AND ProcessName != "msedge.exe"
| stats count by ProcessName, ObjectName
```

**PowerShell Detection:**
```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4656
} | Where-Object {
    $_.Message -like "*Login Data*" -and
    $_.Message -notlike "*chrome.exe*" -and
    $_.Message -notlike "*msedge.exe*"
}
```

## Testing Your Security Posture

### Exercise 1: Detection Testing
1. Deploy Process Monitor or EDR solution
2. Run the audit script
3. Check if alerts are triggered
4. Review detection rules effectiveness

### Exercise 2: Obfuscation Testing
1. Try running the script as-is (usually not detected)
2. Compile to `.exe` using PyInstaller
3. Test with Windows Defender
4. Observe detection rates

### Exercise 3: Alternative Storage
1. Install a password manager (Bitwarden)
2. Move passwords from browser to manager
3. Run the script again
4. Notice: No credentials found (defense works!)

## Troubleshooting

### "Login Data file not found"
- Browser may not have saved passwords
- Using a different browser profile
- Browser not installed

### "Cannot access Login Data file"
- Browser is running (file is locked)
- Close browser completely
- Run script as administrator

### "Failed to decrypt master key"
- Running as different user than browser owner
- Corrupted Local State file
- Unsupported encryption method

### "Missing required library"
```bash
pip install pycryptodome pypiwin32
```

## Limitations

- **Windows Only**: DPAPI is Windows-specific
- **Chromium Browsers Only**: Firefox uses different encryption
- **User Context**: Must run as same user who saved passwords
- **Browser Lock**: Browser must be closed to access Login Data

## Security Considerations

### Why This Works
- Browsers store passwords for convenience
- Encryption relies on user's Windows credentials
- Same user can decrypt their own data
- No additional authentication required

### Why It's Dangerous
- Malware running as user can extract all passwords
- No additional authentication layer
- Passwords stored in plaintext after decryption
- No alerting on access

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
