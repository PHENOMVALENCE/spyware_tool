# Browser Credential Audit - GUI Version

## Overview

A user-friendly graphical interface for the Browser Credential Security Audit Tool. This GUI makes it easy to perform security audits without using the command line.

## Features

### 🎨 Modern Interface
- Clean, intuitive design
- Real-time progress indicators
- Color-coded status messages
- Scrollable results table

### 📊 Key Features
- **Browser Selection**: Dropdown to choose from Chrome, Edge, Brave, Opera, Vivaldi
- **Live Logging**: Real-time log output showing each step of the audit process
- **Results Table**: Structured display of extracted credentials with:
  - URL
  - Username
  - Password (encrypted status shown)
  - Last Used date
  - Usage count
- **Export Functionality**: Save results to text/CSV files
- **Status Updates**: Visual feedback on audit progress

### 🔒 Security Features
- Confirmation dialog before running audit
- Clear warnings about educational use
- Status indicators for audit state

## How to Run

### Option 1: Double-Click (Easiest)
1. Double-click `run_gui.bat`
2. The GUI window will open

### Option 2: Command Line
```cmd
python browser_credential_audit_gui.py
```

### Option 3: PowerShell
```powershell
python browser_credential_audit_gui.py
```

## Usage Instructions

### Step 1: Prepare
- **Close your browser completely** (check Task Manager)
- Make sure you're logged in as the Windows user who saved the passwords

### Step 2: Select Browser
- Use the dropdown menu to select your browser
- Options: Chrome, Edge, Brave, Opera, Vivaldi

### Step 3: Run Audit
- Click the **"Run Audit"** button
- Confirm the dialog
- Watch the progress bar and log output

### Step 4: Review Results
- Results appear in the table below
- Check the log area for detailed information
- Review each credential entry

### Step 5: Export (Optional)
- Click **"Export Results"** to save to a file
- Choose location and filename
- Results saved in structured text format

### Simulation flow (Monitor → Collect → Export)
The tool simulates what an infostealer can access:

1. **Monitor / Access** – Reads browser data: saved passwords, history, download history, cache, and files in the Downloads folder.
2. **Collect** – Gathers all of the above into one report (shown in the Credentials, History, Downloads, Cache Files, Downloaded Files, and Detection tabs).
3. **Simulate exfiltration** – Use the **"Simulation Summary"** tab and **"Export simulation report"** to save the full report to a **local file** (JSON or TXT). No data is sent over the network. For training, you can hand this file to your trainer.

## GUI Components

### Control Panel (Left Side)
- **Browser Selection**: Dropdown menu
- **Run Audit**: Start the credential extraction
- **Export Results**: Save findings to file
- **Clear Results**: Reset the interface
- **Status Indicator**: Current operation status
- **Progress Bar**: Visual progress indicator
- **Information Panel**: Important warnings and requirements

### Results Panel (Right Side) – Tabs
- **Credentials**: Saved passwords (URL, Username, Password, Last Used, Times Used)
- **History**: Browser history entries
- **Downloads**: Download history from the browser
- **Cache Files**: HTML/CSS/JS files in browser cache
- **Downloaded Files**: Files in the user’s Downloads folder (with suspicious indicators)
- **Detection**: Unauthorized access detection results
- **Simulation Summary**: What was monitored/collected and **Export simulation report** (local file only, no network)

### Log Area (Bottom)
- Real-time log output
- Color-coded messages:
  - **Green**: Success messages
  - **Red**: Error messages
  - **Orange**: Warning messages
  - **Black**: Info messages

## Troubleshooting

### GUI Won't Start
- Make sure Python is installed: `python --version`
- Check dependencies: `pip list | findstr pycryptodome`
- Try running from command line to see error messages

### "No module named 'browser_credential_audit'"
- Make sure `browser_credential_audit.py` is in the same directory
- Check file name spelling (case-sensitive on some systems)

### Audit Fails
- **Close browser completely** (most common issue)
- Check you're running as the correct Windows user
- Verify browser has saved passwords
- Check log area for specific error messages

### No Results Displayed
- Browser may not have saved passwords
- Using a different browser profile
- Check log for specific messages

## Keyboard Shortcuts

- **Ctrl+C**: Copy selected text (in log area)
- **Ctrl+A**: Select all (in log area)
- **Tab**: Navigate between controls
- **Enter**: Activate focused button

## Export Format

Exported files include:
- Header with timestamp
- Structured table format
- All credential details
- Summary count

Example:
```
================================================================================
Browser Credential Audit Results
Generated: 2024-01-15 14:30:22
================================================================================

URL                                               | Username                      | Password                   | Last Used            | Times Used
----------------------------------------------------------------------------------------------------
https://accounts.google.com                       | user@example.com              | [ENCRYPTED]                | 2024-01-14 10:15:33  | 45
...
```

## Requirements

- Python 3.7+
- tkinter (usually included with Python)
- pycryptodome
- pypiwin32
- Windows OS (for DPAPI)

## Notes

- The GUI uses the same underlying audit engine as the command-line version
- All security warnings and educational notices are displayed
- Results are displayed in real-time as they're extracted
- Export functionality preserves all credential details

## Comparison: GUI vs Command Line

| Feature | GUI | Command Line |
|---------|-----|--------------|
| Ease of Use | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| Visual Feedback | ✅ | ❌ |
| Progress Indicators | ✅ | ❌ |
| Export Functionality | ✅ | ✅ |
| Logging | ✅ (Visual) | ✅ (Text) |
| Automation | ❌ | ✅ |

Choose the GUI for interactive use, command-line for scripting/automation.
