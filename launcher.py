import subprocess
import time
import webview
import sys
import requests
import atexit
import os

# ==========================
# PATH SETUP
# ==========================

if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

BACKEND_DIR = os.path.join(BASE_DIR, "backend")

print("BASE_DIR:", BASE_DIR)
print("BACKEND_DIR:", BACKEND_DIR)

if not os.path.exists(BACKEND_DIR):
    print("ERROR: Backend folder not found!")
    print(BACKEND_DIR)
    sys.exit(1)

# ==========================
# PYTHON EXECUTABLE
# ==========================

python_exe = os.path.join(
    BACKEND_DIR,
    "venv",
    "Scripts",
    "python.exe"
)

if not os.path.isfile(python_exe):
    print("Python executable not found:")
    print(python_exe)
    sys.exit(1)


# ==========================
# START BACKEND
# ==========================

try:
    backend = subprocess.Popen(
    [
        python_exe,
        "-m",
        "uvicorn",
        "main:app",
        "--host",
        "127.0.0.1",
        "--port",
        "8000"
    ],
    cwd=BACKEND_DIR,
    creationflags=subprocess.CREATE_NO_WINDOW,
    
)

except Exception as e:
    print("Failed to start backend")
    print(e)
    sys.exit(1)

# ==========================
# CLEANUP
# ==========================

def shutdown_backend():
    try:
        if backend.poll() is None:
            backend.terminate()
            backend.wait(timeout=5)
    except Exception:
        pass


atexit.register(shutdown_backend)

# ==========================
# WAIT FOR BACKEND
# ==========================

print("Waiting for backend...")

for _ in range(60):
    try:
        response = requests.get(
            "http://127.0.0.1:8000",
            timeout=2
        )

        if response.status_code in [200, 404]:
            print("Backend ready.")
            break

    except Exception:
        pass

    time.sleep(1)

else:
    print("Backend failed to start.")
    shutdown_backend()
    sys.exit(1)

# ==========================
# OPEN WINDOW
# ==========================

webview.create_window(
    title="PHOENIX Threat Detection System",
    url="http://127.0.0.1:8000",
    width=1600,
    height=900,
    resizable=True
)

webview.start()