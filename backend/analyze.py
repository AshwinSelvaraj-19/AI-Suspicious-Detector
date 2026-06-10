import psutil

from hash_engine import calculate_sha256
from signature_checker import verify_signature
from virustotal import lookup_hash
from trust_engine import calculate_trust


def analyze_process(pid):

    try:
        process = psutil.Process(pid)

        exe_path = process.exe()

        sha256 = calculate_sha256(exe_path)

        signature = verify_signature(exe_path)

        vt_result = lookup_hash(sha256)

        # Location Classification
        exe_lower = exe_path.lower()

        if (
            exe_lower.startswith(r"c:\windows\system32")
            or exe_lower.startswith(r"c:\program files")
            or exe_lower.startswith(r"c:\program files (x86)")
        ):
            location_classification = "Trusted"
        else:
            location_classification = "Unknown"

        # Trust Score
        trust_score = calculate_trust(
            publisher=signature["publisher"],
            signature_status=signature["status"],
            virustotal=vt_result,
            location_classification=location_classification
        )

        # Verdict Mapping
        if trust_score >= 80:
            verdict = "Trusted"

        elif trust_score >= 60:
            verdict = "Likely Legitimate"

        elif trust_score >= 40:
            verdict = "Unverified"

        elif trust_score >= 20:
            verdict = "Suspicious"

        else:
            verdict = "High Risk"

        return {
            "pid": pid,
            "process_name": process.name(),
            "exe_path": exe_path,
            "sha256": sha256,

            "publisher": signature["publisher"],
            "signature_status": signature["status"],

            "location_classification": location_classification,

            "trust_score": trust_score,
            "verdict": verdict,

            "virustotal": vt_result
        }

    except Exception as e:
        return {
            "error": str(e)
        }