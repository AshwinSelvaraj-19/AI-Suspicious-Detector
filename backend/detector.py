import psutil
from risk_engine import calculate_risk

def get_suspicious_processes():
    suspicious = []

    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'exe']):
        try:
            info = proc.info
            score, reasons, loc_class, is_signed = calculate_risk(info)

            # Threshold set to 15 to map SAFE, LOW, MEDIUM, HIGH, CRITICAL correctly
            if score >= 15:
                info["risk_score"] = score
                info["reasons"] = reasons
                info["location_classification"] = loc_class
                info["digital_signature"] = "Signed" if is_signed else "Unsigned"

                # Capture Parent Process Analysis
                try:
                    parent = proc.parent()
                    info["parent_name"] = parent.name() if parent else "N/A"
                    info["parent_pid"] = parent.pid if parent else "N/A"
                except Exception:
                    info["parent_name"] = "N/A"
                    info["parent_pid"] = "N/A"

                # Map threat levels consistently
                if score >= 80:
                    info["threat_level"] = "CRITICAL"
                elif score >= 55:
                    info["threat_level"] = "HIGH"
                elif score >= 35:
                    info["threat_level"] = "MEDIUM"
                else:
                    info["threat_level"] = "LOW"

                suspicious.append(info)

        except Exception as e:
            # Silently catch processes that terminate during iteration
            pass

    return suspicious