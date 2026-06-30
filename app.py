from flask import Flask, render_template, jsonify, request
import threading
import time
import os
import psutil
import pandas as pd
import joblib
import math
import warnings

warnings.filterwarnings("ignore")

app = Flask(__name__)

# Global states
is_monitoring = False
live_logs = []
pending_threat_pid = None
custom_scan_results = []

model_file = "../3_saved_ai_models/ransomware_predict_model.pkl"
WHITELIST = ["explorer.exe", "svchost.exe", "system", "chrome.exe", "code.exe", "python.exe"]

try:
    model = joblib.load(model_file)
except:
    model = None

def calculate_entropy(file_path):
    """Calculates the Shannon Entropy of a file to detect ransomware encryption (Max: 8.0)."""
    if not os.path.exists(file_path) or os.path.isdir(file_path):
        return 0
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy
    except:
        return 0

def background_ai_scanner():
    """Monitors live RAM processes using AI."""
    global is_monitoring, live_logs, pending_threat_pid
    while is_monitoring:
        for proc in psutil.process_iter(['pid', 'name', 'num_threads']):
            if not is_monitoring: break
            while pending_threat_pid:
                time.sleep(0.5)

            try:
                p_info = proc.info
                threads = p_info['num_threads']
                sim_id = 11 if threads > 15 else 1
                sim_act = 2 if threads > 30 else 0
                
                if model:
                    data = pd.DataFrame([[sim_id, sim_act]], columns=['EventID', 'Action_Code'])
                    pred = model.predict(data)
                    
                    if pred[0] == 1 and p_info['name'].lower() not in WHITELIST:
                        live_logs.insert(0, f"[ALERT] MALICIOUS PROCESS: {p_info['name']} (PID: {p_info['pid']})")
                        pending_threat_pid = p_info['pid']
                    else:
                        live_logs.insert(0, f"Inspecting Process: {p_info['name']}... [SECURE]")
                time.sleep(0.2)
            except: pass
        time.sleep(2)

@app.route('/')
def index(): return render_template('index.html')

@app.route('/start', methods=['POST'])
def start():
    global is_monitoring
    is_monitoring = True
    threading.Thread(target=background_ai_scanner, daemon=True).start()
    return jsonify({"status": "running"})

@app.route('/stop', methods=['POST'])
def stop():
    global is_monitoring, pending_threat_pid
    is_monitoring = False
    pending_threat_pid = None
    return jsonify({"status": "stopped"})

@app.route('/get_logs')
def logs(): return jsonify({"logs": live_logs[:20]})

@app.route('/resolve', methods=['POST'])
def resolve():
    global pending_threat_pid
    action = request.json.get('action')
    if action == 'kill' and pending_threat_pid:
        try: os.kill(pending_threat_pid, 9) # Hard kill process via OS
        except: pass
    pending_threat_pid = None
    return jsonify({"status": "done"})

# --- NEW PRO FEATURE: CUSTOM FILE/FOLDER SCANNER ---
@app.route('/scan_custom_folder', methods=['POST'])
def scan_custom_folder():
    target_path = request.json.get('path')
    if not os.path.exists(target_path):
        return jsonify({"status": "error", "message": "Path does not exist!"})

    flagged_files = []
    
    # If it's a single file
    if os.path.isfile(target_path):
        entropy = calculate_entropy(target_path)
        if entropy > 7.5: # Highly random data, typical of encrypted ransomware files
            flagged_files.append({"file": target_path, "reason": f"High Entropy ({entropy:.2f}) - Suspected Ransomware Victim!"})
    
    # If it's a directory, perform deep scan
    elif os.path.isdir(target_path):
        for root, dirs, files in os.walk(target_path):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Check 1: Extension analysis
                suspicious_extensions = ['.locked', '.crypto', '.wacry', '.ransom']
                if any(file_path.endswith(ext) for ext in suspicious_extensions):
                    flagged_files.append({"file": file_path, "reason": "Known Ransomware Extension Detected!"})
                    continue
                
                # Check 2: Heuristic Heuristic Entropy Check
                entropy = calculate_entropy(file_path)
                if entropy > 7.6 and not file.endswith(('.zip', '.rar', '.7z', '.png', '.jpg')): # Ignore compressed/media files
                    flagged_files.append({"file": file_path, "reason": f"High File Randomness/Entropy ({entropy:.2f})"})

    return jsonify({"status": "success", "results": flagged_files})

if __name__ == '__main__':
    app.run(debug=True, port=5000)