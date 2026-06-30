import pandas as pd
import joblib
import time
import os
import psutil
import warnings

# Hide unnecessary warnings
warnings.filterwarnings("ignore")

print("==================================================")
print("🔥 AI RANSOMWARE DETECTOR: INTERACTIVE MODE 🔥")
print("==================================================")

model_file = "../3_saved_ai_models/ransomware_predict_model.pkl"

# Whitelist: Essential system processes that the AI will ignore
WHITELIST = ["explorer.exe", "svchost.exe", "system", "chrome.exe", "code.exe", "cmd.exe", "python.exe"]

def ask_and_neutralize(pid, process_name):
    """This function asks for user permission before taking action on a suspicious process."""
    if process_name.lower() in WHITELIST:
        return # Safeguard: Do not touch whitelisted processes
    
    print(f"\n[!!!] ALERT: AI detected suspicious behavior in '{process_name}' (PID: {pid})")
    
    # Ask the user for live permission
    user_choice = input(f"❓ Do you want to KILL/BLOCK '{process_name}'? (y/n): ")
    
    if user_choice.lower() in ['y', 'yes']:
        try:
            print(f"   [☠️] EXECUTING TERMINATION ON PID: {pid} ({process_name})...")
            target_process = psutil.Process(pid)
            target_process.terminate()
            print("   [+] PROCESS KILLED SUCCESSFULLY!\n")
        except psutil.NoSuchProcess:
            print("   [-] Process has already been terminated.\n")
        except psutil.AccessDenied:
            print("   [-] Access Denied. Please run CMD as 'Administrator' to kill this process.\n")
        except Exception as e:
            print(f"   [-] Error: {e}\n")
    else:
        print(f"   [🛡️] IGNORED: Permission denied by user. '{process_name}' will keep running.\n")

try:
    print("[*] Loading AI Brain...")
    model = joblib.load(model_file)
    print("[+] AI Active! Monitoring Live System... (Press Ctrl+C to stop)\n")
    print("-" * 60)
    
    while True:
        for proc in psutil.process_iter(['pid', 'name', 'num_threads']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                threads = proc.info['num_threads']
                
                # Simulation Logic based on Threads
                simulated_event_id = 11 if threads > 15 else 1
                simulated_action = 2 if threads > 30 else 0
                
                # AI Prediction
                data_for_ai = pd.DataFrame([[simulated_event_id, simulated_action]], columns=['EventID', 'Action_Code'])
                prediction = model.predict(data_for_ai)
                
                # If AI detects ransomware, trigger the interactive neutralization function
                if prediction[0] == 1 and name.lower() not in WHITELIST:
                    ask_and_neutralize(pid, name)
                    # Pause to prevent terminal flooding if the process isn't killed immediately
                    time.sleep(1) 
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
        # Scan the system every 5 seconds
        time.sleep(5)

except FileNotFoundError:
    print(f"[-] Error: AI Model not found. Please run Step 2 first.")
except KeyboardInterrupt:
    print("\n[+] Detector stopped by user. System is exposed.")