# Browser Data Guard – Security Extension

A simple **Chrome/Edge security awareness extension** that explains how infostealer-style attacks work and how to defend against them. It does **not** block the simulator tool directly (extensions cannot stop other programs from reading files on disk), but it promotes safer habits.

## What it does

- **Popup** with:
  - What’s at risk: saved passwords, browser cache, download history, Downloads folder.
  - How to defend: use a password manager, close the browser when away, keep the system updated, avoid storing sensitive files only in Downloads.

## How to install (Chrome / Edge)

1. Open Chrome or Edge.
2. Go to `chrome://extensions` (or `edge://extensions`).
3. Turn **Developer mode** ON (top right).
4. Click **Load unpacked**.
5. Select the folder: `browser_security_extension` (this folder).
6. The extension icon will appear in the toolbar; click it to open the popup.

## Files

- `manifest.json` – Extension manifest (Manifest V3).
- `popup.html` – Popup content and tips.
- `popup.css` – Popup styling.

## Note

This extension does **not** read your passwords, history, or cache. It has no permissions and only shows static advice. Real protection comes from using a password manager, closing the browser when not in use, and keeping the OS and AV updated.
