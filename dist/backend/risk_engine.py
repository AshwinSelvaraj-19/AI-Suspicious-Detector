import os
import re

try:
    import winreg
except ImportError:
    winreg = None


def check_persistence(exe_path):
    if not exe_path:
        return False

    name = os.path.basename(exe_path).lower()

    try:
        user_startup = os.path.expandvars(
            r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
        )

        common_startup = os.path.expandvars(
            r"%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup"
        )

        for folder in [user_startup, common_startup]:
            if os.path.exists(folder):
                for item in os.listdir(folder):
                    if name in item.lower():
                        return True
    except:
        pass

    if winreg:
        paths = [
            (
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run"
            ),
            (
                winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\Run"
            )
        ]

        for hkey, subkey in paths:
            try:
                with winreg.OpenKey(
                    hkey,
                    subkey,
                    0,
                    winreg.KEY_READ
                ) as key:

                    i = 0

                    while True:
                        try:
                            val_name, val_data, val_type = winreg.EnumValue(key, i)

                            if name in str(val_data).lower():
                                return True

                            i += 1

                        except OSError:
                            break

            except:
                pass

    return False




def calculate_risk(process):

    score = 0
    reasons = []

    name = str(process.get("name", "")).lower()
    cpu = process.get("cpu_percent", 0) or 0
    memory = process.get("memory_percent", 0) or 0
    exe = str(process.get("exe", "")).lower()

    # ---------------------------
    # LOCATION CLASSIFICATION
    # ---------------------------

    location_classification = "Unknown"

    if exe:

        if exe.startswith(r"c:\windows\system32"):
            location_classification = "Trusted"

        elif exe.startswith(r"c:\program files"):
            location_classification = "Trusted"

        elif exe.startswith(r"c:\program files (x86)"):
            location_classification = "Trusted"

        elif r"\temp" in exe or r"\tmp" in exe:
            location_classification = "Suspicious"

        elif r"\downloads" in exe:
            location_classification = "Suspicious"

        elif r"\desktop" in exe:
            location_classification = "Suspicious"

        elif "appdata" in exe:
            location_classification = "User Space"

    # ---------------------------
    # LOCATION SCORING
    # ---------------------------

    if r"\temp" in exe or r"\tmp" in exe:
        score += 35
        reasons.append("Running From Temp Folder")

    elif r"\downloads" in exe:
        score += 25
        reasons.append("Running From Downloads Folder")

    elif r"\desktop" in exe:
        score += 20
        reasons.append("Running From Desktop Folder")

    # ---------------------------
    # STARTUP PERSISTENCE
    # ---------------------------

    if check_persistence(exe):
        score += 20
        reasons.append("Startup Persistence Detected")

    # ---------------------------
    # HIDDEN DIRECTORY
    # ---------------------------

    if exe:

        parts = exe.replace("/", "\\").split("\\")

        if any(
            part.startswith(".") and len(part) > 1
            for part in parts
        ):
            score += 25
            reasons.append("Hidden Directory")

    # ---------------------------
    # RANDOMIZED FILE NAME
    # ---------------------------

    filename_without_ext = (
        name.replace(".exe", "")
        .lower()
    )

    if (
        len(filename_without_ext) >= 8
        and re.fullmatch(
            r"[a-f0-9]{8,}",
            filename_without_ext
        )
    ):
        score += 20
        reasons.append("Randomized Executable Name")

    # ---------------------------
    # MALWARE KEYWORDS
    # ---------------------------

    keywords = [
        "miner",
        "keylogger",
        "payload",
        "injector",
        "stealer",
        "rat",
        "exploit"
    ]

    if any(keyword in name for keyword in keywords):
        score += 35
        reasons.append("Suspicious Name Pattern")

    # ---------------------------
    # CPU ANALYSIS
    # ---------------------------

    if cpu > 90:
        score += 20
        reasons.append("Very High CPU Usage")

    elif cpu > 70:
        score += 10
        reasons.append("High CPU Usage")

    # ---------------------------
    # MEMORY ANALYSIS
    # ---------------------------

    if memory > 20:
        score += 15
        reasons.append("Very High Memory Usage")

    elif memory > 10:
        score += 5
        reasons.append("High Memory Usage")

    # ---------------------------
    # SAFE PROCESS LIST
    # ---------------------------

    safe_apps = {
        "chrome.exe",
        "discord.exe",
        "code.exe",
        "explorer.exe",
        "msmpeng.exe",
        "taskmgr.exe",
        "searchhost.exe",
        "searchapp.exe",
        "runtimebroker.exe",
        "svchost.exe",
        "dwm.exe",
        "system",
        "spoolsv.exe",
        "lsass.exe",
        "services.exe",
        "wininit.exe",
        "csrss.exe",
        "smss.exe",
        "firefox.exe",
        "msedge.exe",
        "steam.exe",
        "spotify.exe",
        "applicationframehost.exe",
        "securityhealthservice.exe",
        "securityhealthsystray.exe",
        "searchindexer.exe",
        "trustedinstaller.exe",
        "fontdrvhost.exe",
        "taskhostw.exe",
        "textinputhost.exe",
        "shellexperiencehost.exe",
        "startmenuexperiencehost.exe",
        "registry",
        "memcompression",
        "system idle process"
    }

    if (
        name
        and name not in safe_apps
        and location_classification == "Suspicious"
    ):
        score += 5
        reasons.append(
            "Unknown App In Suspicious Location"
        )

    score = min(score, 100)

    return (
        score,
        reasons,
        location_classification,
        True
    )