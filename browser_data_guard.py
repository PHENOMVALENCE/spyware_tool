"""
Browser Data Guard – Block simulator/infostealer access to browser files
========================================================================

Runs on Windows and holds an EXCLUSIVE lock on Chrome/Edge sensitive files
(Login Data, History) so no other process (including the audit simulator)
can read or copy them.

Usage:
  1. Close Chrome/Edge completely.
  2. Run: python browser_data_guard.py   (or python browser_data_guard.py --force)
  3. Keep this window open. Run the simulator in another window – it must fail.
  4. Press Ctrl+C to stop the guard.

Requires: Windows. No extra pip packages.
"""

import os
import sys
import ctypes
from ctypes import wintypes
from pathlib import Path

# Windows constants
GENERIC_READ = 0x80000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
LOCKFILE_EXCLUSIVE_LOCK = 0x2

# Main browser processes only (guard exits if any of these run)
# msedgewebview2.exe not included so guard can try to lock Edge; if WebView2 holds files, lock fails and we show hint
BROWSER_PROCESS_NAMES = frozenset({
    "chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "vivaldi.exe",
})


def _get_profile_dirs(base: Path):
    """Return profile folder names: Default, Profile 1, Profile 2, System Profile, etc."""
    if not base or not base.is_dir():
        return []
    profiles = []
    try:
        for item in base.iterdir():
            if not item.is_dir():
                continue
            name = item.name
            if name == "Default" or name.startswith("Profile ") or name == "System Profile":
                profiles.append(name)
    except (PermissionError, OSError):
        pass
    return sorted(profiles)


def _files_for_base(base: Path):
    """Return list of (Login Data, History) paths that exist under this base. Same logic as simulator."""
    files = []
    # Always try Default first (exact path simulator uses)
    for profile in ["Default"] + [p for p in _get_profile_dirs(base) if p != "Default"]:
        profile_dir = base / profile
        for name in ("Login Data", "History"):
            p = profile_dir / name
            if p.exists():
                files.append(p)
    return files


def _get_guard_paths(browser_name="Chrome"):
    """Return (base_path, list of Login Data and History paths). For Edge, try multiple possible bases."""
    local_app_data = os.getenv("LOCALAPPDATA")
    if not local_app_data:
        return None, []
    base_paths = {
        "Chrome": [Path(local_app_data) / "Google" / "Chrome" / "User Data"],
        "Edge": [
            Path(local_app_data) / "Microsoft" / "Edge" / "User Data",
            Path(local_app_data) / "Microsoft Edge" / "User Data",  # alternate
        ],
        "Brave": [Path(local_app_data) / "BraveSoftware" / "Brave-Browser" / "User Data"],
        "Opera": [Path(local_app_data) / "Opera Software" / "Opera Stable" / "User Data"],
        "Vivaldi": [Path(local_app_data) / "Vivaldi" / "User Data"],
    }
    bases = base_paths.get(browser_name, [])
    for base in bases:
        if not base or not base.exists():
            continue
        files = _files_for_base(base)
        if files:
            return base, files
    return None, []


def _is_browser_running():
    """True if any Chromium browser process is running (by exact image name)."""
    try:
        import subprocess
        out = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH", "/V"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=0x0800 if sys.platform == "win32" else 0,  # CREATE_NO_WINDOW
        )
        if out.returncode != 0:
            return False
        # First column is image name in quotes, e.g. "chrome.exe"
        for line in (out.stdout or "").strip().splitlines():
            if not line.startswith('"'):
                continue
            end = line.find('"', 1)
            if end == -1:
                continue
            name = line[1:end].strip().lower()
            if name in BROWSER_PROCESS_NAMES:
                return True
        return False
    except Exception:
        return False


def _get_last_error():
    return ctypes.get_last_error()


def _open_and_lock(path: Path):
    """
    Open file with share mode 0 (exclusive) and lock first byte with LockFile.
    Returns (handle, None) on success, (None, error_msg) on failure.
    """
    kernel32 = ctypes.windll.kernel32
    path_str = str(path.resolve())
    # Share mode 0 = no other process can open the file
    handle = kernel32.CreateFileW(
        path_str,
        GENERIC_READ,
        0,  # dwShareMode = 0 (exclusive)
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        err = _get_last_error()
        err_map = {
            5: "Access denied",
            32: "File in use by another process",
            2: "File not found",
            3: "Path not found",
        }
        msg = err_map.get(err, f"Error code {err}")
        return None, msg
    # Byte-range lock on first byte (extra lock)
    if kernel32.LockFile(handle, 0, 0, 1, 0) == 0:
        kernel32.CloseHandle(handle)
        return None, "LockFile failed"
    return handle, None


def _close_handle(handle):
    if handle is not None and handle != INVALID_HANDLE_VALUE:
        kernel32 = ctypes.windll.kernel32
        kernel32.UnlockFile(handle, 0, 0, 1, 0)
        kernel32.CloseHandle(handle)


def is_browser_running():
    """True if Chrome, Edge, or another supported browser process is running."""
    return _is_browser_running()


def acquire_locks(force=False):
    """
    Lock browser Login Data and History files (Chrome, Edge, etc.).
    Returns (handles, locked_paths, status_text).
    handles: list of Windows handles to pass to release_locks().
    locked_paths: list of (browser_name, path).
    status_text: multi-line string describing what was locked or any errors.
    """
    handles = []
    locked_paths = []
    lines = []
    if not force and _is_browser_running():
        return [], [], "Chrome or Edge is still running.\nClose the browser completely, then try again."
    browsers_to_try = ["Chrome", "Edge", "Brave", "Opera", "Vivaldi"]
    per_browser_failed = {}
    for browser_name in browsers_to_try:
        base, paths = _get_guard_paths(browser_name)
        if not paths:
            continue
        for path in paths:
            h, err = _open_and_lock(path)
            if h is not None:
                handles.append(h)
                locked_paths.append((browser_name, path))
            else:
                per_browser_failed.setdefault(browser_name, []).append(f"{path.name}: {err}")
    for name, path in locked_paths:
        lines.append(f"  • {name}: {path.parent.name}/{path.name}")
    for name, errs in per_browser_failed.items():
        for e in errs:
            lines.append(f"  [WARN] {name} – {e}")
    if per_browser_failed and "Edge" in per_browser_failed:
        lines.append("  → To lock Edge: end msedge.exe and msedgewebview2.exe in Task Manager, then Start again.")
    if not handles:
        return [], [], "No files could be locked.\nClose Chrome/Edge (and WebView2 for Edge), then try again.\n\n" + "\n".join(lines) if lines else "No browser data found."
    status = "Simulator is BLOCKED. Locked:\n" + "\n".join(lines)
    return handles, locked_paths, status


def release_locks(handles):
    """Release all locked file handles. Call when stopping protection."""
    for h in handles:
        _close_handle(h)


def _verify_lock(path: Path):
    """Try to open the file from a subprocess; should fail if guard holds exclusive lock."""
    try:
        import subprocess
        env = os.environ.copy()
        env["_GUARD_TEST_PATH"] = str(path.resolve())
        r = subprocess.run(
            [
                sys.executable,
                "-c",
                "import os; open(os.environ['_GUARD_TEST_PATH'], 'rb')",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode != 0:
            err = (r.stderr or "") + (r.stdout or "")
            if "PermissionError" in err or "Errno 13" in err or "being used" in err.lower() or "access" in err.lower():
                return True
        return False
    except Exception:
        return False


def main():
    if sys.platform != "win32":
        print("This guard only works on Windows.")
        sys.exit(1)

    force = "--force" in sys.argv or "-f" in sys.argv

    print("Browser Data Guard – exclusive lock on browser files")
    print("=" * 55)

    if not force and _is_browser_running():
        print("\n[STOP] Chrome, Edge, or another supported browser is running.")
        print("Close it completely, then run this again (or use --force to try anyway).\n")
        sys.exit(1)

    browsers_to_try = ["Chrome", "Edge", "Brave", "Opera", "Vivaldi"]
    handles = []
    locked_paths = []
    per_browser_locked = {}
    per_browser_failed = {}

    for browser_name in browsers_to_try:
        base, paths = _get_guard_paths(browser_name)
        if not paths:
            per_browser_locked[browser_name] = 0
            if browser_name == "Edge":
                edge_std = Path(os.getenv("LOCALAPPDATA", "")) / "Microsoft" / "Edge" / "User Data" / "Default" / "Login Data"
                print(f"  [INFO] Edge: no files found. Expected path: {edge_std}")
            continue
        locked_this = 0
        failed_this = []
        for path in paths:
            h, err = _open_and_lock(path)
            if h is not None:
                handles.append(h)
                locked_paths.append((browser_name, path))
                locked_this += 1
            else:
                failed_this.append(f"{path.name}: {err}")
                if browser_name == "Edge":
                    print(f"  [INFO] Edge path tried: {path}")
        per_browser_locked[browser_name] = locked_this
        if failed_this:
            per_browser_failed[browser_name] = failed_this

    print("\nLock result:")
    for name, count in per_browser_locked.items():
        if count > 0:
            print(f"  {name}: {count} file(s) locked")
    for name, errs in per_browser_failed.items():
        for e in errs:
            print(f"  [WARN] {name} – {e}")
    if per_browser_failed and "Edge" in per_browser_failed:
        print("\n  → To lock Edge: open Task Manager → Details → end ALL 'msedge.exe' and 'msedgewebview2.exe', then run the guard again.")

    if not handles:
        print("\n[ERROR] No files could be locked.")
        print("Ensure Chrome or Edge is installed and fully closed (or use --force).")
        sys.exit(1)

    print("\n[OK] Guard is ACTIVE. Locked files (exclusive + byte lock):")
    for name, p in locked_paths:
        print(f"  • {name}: {p.parent.name}/{p.name}")

    # Verify one lock so user knows it works
    first_path = locked_paths[0][1]
    if _verify_lock(first_path):
        print("\n[VERIFIED] Lock works: another process cannot open these files.")
    else:
        print("\n[INFO] Run the simulator now; it should get 'Permission denied' or 'file in use'.")

    print("\n  → Keep this window OPEN. Run the simulator in another window – it must fail.")
    print("  → Press Ctrl+C here to stop the guard and release the files.\n")

    try:
        while True:
            ctypes.windll.kernel32.Sleep(1000)
    except KeyboardInterrupt:
        pass
    finally:
        for h in handles:
            _close_handle(h)
        print("\n[OK] Guard stopped. Files released.")


if __name__ == "__main__":
    main()
