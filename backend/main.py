from fastapi import FastAPI
import psutil
from datetime import datetime
import csv
import io
from fastapi.responses import StreamingResponse
from detector import get_suspicious_processes
from summary import get_summary
from system_stats import get_system_stats
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Phoenix Security Core")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global in-memory history log
history_records = []

def update_history_log(suspicious_list):
    existing = {(r["pid"], r["name"]): r["risk_score"] for r in history_records}
    for p in suspicious_list:
        key = (p["pid"], p["name"])
        if key not in existing or existing[key] != p["risk_score"]:
            history_records.append({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "pid": p["pid"],
                "name": p["name"],
                "risk_score": p["risk_score"],
                "threat_level": p["threat_level"]
            })
    # Cap history at 50 records
    if len(history_records) > 50:
        del history_records[:-50]

@app.get("/")
def home():
    return {"message": "Phoenix Threat Detection System API Running"}

@app.get("/processes")
def get_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            processes.append(proc.info)
        except Exception:
            pass
    return processes

@app.get("/suspicious")
def suspicious():
    data = get_suspicious_processes()
    update_history_log(data)
    return data

@app.get("/summary")
def summary():
    return get_summary()

@app.get("/system_stats")
def system():
    return get_system_stats()

@app.get("/history")
def get_history():
    # Return history list sorted by timestamp descending
    return sorted(history_records, key=lambda x: x["timestamp"], reverse=True)

@app.get("/network")
def get_network_connections():
    connections = []
    pid_to_name = {}
    
    # Pre-map PIDs to process names for fast lookup
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid_to_name[proc.info['pid']] = proc.info['name']
        except Exception:
            pass

    try:
        # Fetch active inet connections
        for conn in psutil.net_connections(kind='inet'):
            pid = conn.pid
            if pid is None:
                continue
            name = pid_to_name.get(pid, "System/Service")
            
            local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            port = conn.laddr.port if conn.laddr else "N/A"
            state = conn.status
            
            connections.append({
                "pid": pid,
                "name": name,
                "local_address": local_addr,
                "remote_address": remote_addr,
                "port": port,
                "state": state
            })
    except Exception as e:
        print(f"Error reading net_connections: {e}")
        
    return connections

@app.get("/report")
def get_report(format: str = "json"):
    summary_data = get_summary()
    suspicious_list = get_suspicious_processes()
    system_metrics = get_system_stats()

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header Row
        writer.writerow(["Timestamp", "PID", "Process Name", "Risk Score", "Threat Level", "Location Classification", "Digital Signature", "Executable Path"])
        
        # Data Rows
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for p in suspicious_list:
            writer.writerow([
                timestamp_str,
                p.get("pid"),
                p.get("name"),
                p.get("risk_score"),
                p.get("threat_level"),
                p.get("location_classification"),
                p.get("digital_signature"),
                p.get("exe")
            ])
            
        output.seek(0)
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode("utf-8")),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=phoenix_threat_report.csv"}
        )
        
    # Default is JSON report
    return {
        "timestamp": datetime.now().isoformat(),
        "summary": summary_data,
        "system_metrics": system_metrics,
        "suspicious_processes": suspicious_list
    }