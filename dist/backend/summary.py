import psutil
from detector import get_suspicious_processes

def get_summary():
    suspicious = get_suspicious_processes()

    critical = 0
    high = 0
    medium = 0
    low = 0
    safe = 0

    for proc in suspicious:
        level = proc.get("threat_level", "LOW")
        if level == "CRITICAL":
            critical += 1
        elif level == "HIGH":
            high += 1
        elif level == "MEDIUM":
            medium += 1
        elif level == "LOW":
            low += 1
        else:
            safe += 1

    return {
        "total_processes": len(psutil.pids()),
        "suspicious_processes": len(suspicious),
        "critical_risk": critical,
        "high_risk": high,
        "medium_risk": medium,
        "low_risk": low,
        "safe_risk": safe
    }