import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib
import os

print("--- AI Ransomware Detection: Step 2 ---")
print("[+] AI Model Training Started...\n")

# paths of files
input_file = "../1_sysmon_logs_dataset/cleaned_sysmon_events.csv"
model_folder = "../3_saved_ai_models"
model_file = os.path.join(model_folder, "ransomware_predict_model.pkl")

try:
    # 1. for loading the cleaned data from CSV file
    df = pd.read_csv(input_file)
    print(f"[*] Cleaned Dataset Loaded. Found {len(df)} events.")
    
    # 2. for preparing features (X) and labels (y)
    # AI will use 'EventID' and 'Action_Code' for learning
    X = df[['EventID', 'Action_Code']]
    # 'IsMalicious' is our target (0 = safe, 1 = ransomware)
    y = df['IsMalicious']
    
    # 3. for selecting and training the AI model
    # We are using Random Forest Classifier which is best for cybersecurity
    print("[*] Training the Random Forest AI Model...")
    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(X, y)
    
    # 4. for checking the model's accuracy (precision)
    predictions = model.predict(X)
    accuracy = accuracy_score(y, predictions)
    print(f"[+] Model Training Completed. Accuracy: {accuracy * 100:.2f}%")
    
    # 5. for saving the model for future use
    if not os.path.exists(model_folder):
        os.makedirs(model_folder)
        
    joblib.dump(model, model_file)
    print(f"\n[+] Success! Trained AI model saved at: {model_file}")
    print("[*] Now we can use this model for Live Threat Detection (Step 3)!")

except FileNotFoundError:
    print(f"[-] Error: '{input_file}' not found. Please run Step 1 first.")