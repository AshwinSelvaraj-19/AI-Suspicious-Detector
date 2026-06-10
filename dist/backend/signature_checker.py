import subprocess
import json


def verify_signature(file_path):
    try:

        command = [
            "powershell",
            "-Command",
            f"""
            $sig = Get-AuthenticodeSignature '{file_path}';
            [PSCustomObject]@{{
                Status = $sig.Status.ToString()
                Publisher = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Subject }} else {{ "Unknown" }}
            }} | ConvertTo-Json
            """
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return {
                "status": "Unknown",
                "publisher": "Unknown"
            }

        if not result.stdout.strip():
            return {
                "status": "Unknown",
                "publisher": "Unknown"
            }

        data = json.loads(result.stdout)

        return {
            "status": data.get("Status", "Unknown"),
            "publisher": data.get("Publisher", "Unknown")
        }

    except subprocess.TimeoutExpired:
        return {
            "status": "Timeout",
            "publisher": "Unknown"
        }

    except Exception:
        return {
            "status": "Unknown",
            "publisher": "Unknown"
        }