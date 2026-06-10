import psutil
import json

from risk_engine import calculate_risk
from signature_checker import verify_signature
from hash_engine import calculate_sha256


with open("safe_processes.json", "r") as f:
    SAFE_PROCESSES = json.load(f)


def get_suspicious_processes():
    suspicious = []

    for proc in psutil.process_iter([
        "pid",
        "name",
        "cpu_percent",
        "memory_percent",
        "exe"
    ]):
        try:
            info = proc.info

            process_name = (
                info.get("name") or ""
            ).lower()

            # ==========================
            # SAFE PROCESS FILTER
            # ==========================

            if process_name in SAFE_PROCESSES:
                continue

            # ==========================
            # RISK ANALYSIS
            # ==========================

            score, reasons, loc_class, _ = calculate_risk(
                info
            )

            # Ignore low-risk processes
            if score < 15:
                continue

            exe_path = info.get("exe") or ""

            # ==========================
            # DIGITAL SIGNATURE
            # ==========================

            signature_info = verify_signature(
                exe_path
            )

            # ==========================
            # SHA256 HASH
            # ==========================

            sha256_hash = calculate_sha256(
                exe_path
            )

            # ==========================
            # PARENT PROCESS INFO
            # ==========================

            try:
                parent = proc.parent()

                parent_name = (
                    parent.name()
                    if parent
                    else "N/A"
                )

                parent_pid = (
                    parent.pid
                    if parent
                    else "N/A"
                )

            except Exception:
                parent_name = "N/A"
                parent_pid = "N/A"

            # ==========================
            # THREAT LEVEL
            # ==========================

            if score >= 80:
                threat_level = "CRITICAL"

            elif score >= 55:
                threat_level = "HIGH"

            elif score >= 35:
                threat_level = "MEDIUM"

            else:
                threat_level = "LOW"

            suspicious.append({
                **info,

                "risk_score": score,
                "reasons": reasons,

                "location_classification": loc_class,

                "signature_status":
                    signature_info.get(
                        "status",
                        "Unknown"
                    ),

                "publisher":
                    signature_info.get(
                        "publisher",
                        "Unknown"
                    ),

                "sha256":
                    sha256_hash,

                "parent_name":
                    parent_name,

                "parent_pid":
                    parent_pid,

                "threat_level":
                    threat_level
            })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

        except Exception:
            continue

    # Highest risk first
    suspicious.sort(
        key=lambda x: x["risk_score"],
        reverse=True
    )

    return suspicious