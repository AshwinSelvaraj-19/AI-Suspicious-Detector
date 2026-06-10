print("HELLO")

from signature_checker import verify_signature

print("IMPORT OK")

result = verify_signature(
    r"C:\Users\Ashwin\Desktop\PROJECT\AI-Suspicious-Detector\venv\Scripts\uvicorn.exe"
)

print(result)

print("DONE")