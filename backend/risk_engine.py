import os
try:
    import winreg
except ImportError:
    winreg = None

def check_persistence(exe_path):
    if not exe_path or exe_path == "none" or exe_path == "":
        return False
        
    name = os.path.basename(exe_path).lower()
    
    # 1. Check Startup Folders
    try:
        user_startup = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
        common_startup = os.path.expandvars(r"%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup")
        for folder in [user_startup, common_startup]:
            if os.path.exists(folder):
                for item in os.listdir(folder):
                    if name in item.lower():
                        return True
    except:
        pass

    # 2. Check Registry Run Keys
    if winreg:
        paths = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")
        ]
        for hkey, subkey in paths:
            try:
                with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
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

def check_digital_signature(exe_path, location_classification):
    if not exe_path or exe_path == "none" or exe_path == "":
        return False
        
    if location_classification == "Trusted":
        return True
        
    try:
        with open(exe_path, 'rb') as f:
            f.seek(0x3c)
            pe_offset = int.from_bytes(f.read(4), 'little')
            f.seek(pe_offset)
            magic = f.read(4)
            if magic != b'PE\x00\x00':
                return False
            f.seek(pe_offset + 24)
            magic_opt = f.read(2)
            is_pe32_plus = (magic_opt == b'\x0b\x02')
            sec_dir_offset = pe_offset + 168 if is_pe32_plus else pe_offset + 152
            f.seek(sec_dir_offset)
            sec_dir_address = int.from_bytes(f.read(4), 'little')
            sec_dir_size = int.from_bytes(f.read(4), 'little')
            return sec_dir_size > 0
    except:
        return False

def calculate_risk(process):
    score = 0
    reasons = []

    name = process.get("name", "").lower()
    cpu = process.get("cpu_percent", 0)
    memory = process.get("memory_percent", 0)
    exe = str(process.get("exe", "")).lower()

    # 1. Determine Location Classification
    location_classification = "Unknown"
    if exe and exe != "none" and exe != "":
        path_lower = exe.lower()
        if "c:\\windows\\system32" in path_lower or path_lower.startswith("c:\\windows\\system32"):
            location_classification = "Trusted"
        elif "c:\\program files" in path_lower or "c:\\program files (x86)" in path_lower:
            location_classification = "Trusted"
        elif "appdata\\local\\temp" in path_lower or "\\temp" in path_lower or "\\tmp" in path_lower:
            location_classification = "Suspicious"
        elif "\\downloads" in path_lower:
            location_classification = "Suspicious"
        elif "\\desktop" in path_lower:
            location_classification = "Suspicious"
        elif "appdata" in path_lower:
            location_classification = "Suspicious"

    # Location Scoring Bonuses
    if location_classification == "Suspicious":
        if "temp" in exe or "tmp" in exe:
            score += 35
            reasons.append("Running From Temp Folder")
        elif "downloads" in exe:
            score += 30
            reasons.append("Running From Downloads Folder")
        elif "desktop" in exe:
            score += 25
            reasons.append("Running From Desktop Folder")
        elif "appdata" in exe:
            score += 20
            reasons.append("Running From AppData Folder")

    # 2. Digital Signature Analysis
    is_signed = check_digital_signature(exe, location_classification)
    if exe and exe != "none" and exe != "":
        if not is_signed:
            score += 15
            reasons.append("Unsigned Executable")

    # 3. Startup Persistence Heuristics
    if check_persistence(exe):
        score += 20
        reasons.append("Configured for Startup Persistence")

    # 4. Hidden Directory Heuristics
    if exe and exe != "none" and exe != "":
        path_parts = exe.replace("/", "\\").split("\\")
        has_hidden_dir = any(part.startswith(".") and len(part) > 1 for part in path_parts)
        if has_hidden_dir:
            score += 25
            reasons.append("Running From Hidden Directory")
            
        suspicious_keywords = ["miner", "keylogger", "exploit", "payload"]
        if any(kw in name for kw in suspicious_keywords):
            score += 35
            reasons.append("Suspicious Executable Pattern")

    # 5. CPU Heuristics
    if cpu > 60:
        score += 30
        reasons.append("High CPU Usage")
    elif cpu > 25:
        score += 15
        reasons.append("Moderate CPU Usage")

    # 6. Memory Heuristics
    if memory > 8:
        score += 20
        reasons.append("High Memory Usage")
    elif memory > 4:
        score += 10
        reasons.append("Moderate Memory Usage")

    # 7. Trusted Whitelist check
    safe_apps = [
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
        "smss.exe"
    ]

    if name and name not in safe_apps:
        score += 15
        reasons.append("Unknown Application")

    score = min(100, score)

    return score, reasons, location_classification, is_signed