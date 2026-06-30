import pandas as pd
import os

print("--- AI Ransomware Detection: Step 1 ---")
print("[+] Data Cleaning Process Started...\n")

# paths of files
input_file = "../1_sysmon_logs_dataset/raw_sysmon_events.csv"
output_file = "../1_sysmon_logs_dataset/cleaned_sysmon_events.csv"

try:
    # 1. for loading the raw data from CSV file
    df = pd.read_csv(input_file)
    print(f"[*] Raw Data Loaded Successfully. Total events: {len(df)}")
    
    # 2. for cleaning the data (removing empty or invalid entries)
    df = df.dropna() 
    
    # 3. for converting data for AI (AI understands numbers, not words)
    # we are converting the 'Action' column values to numbers
    df['Action_Code'] = df['Action'].astype('category').cat.codes
    
    # 4. for saving the cleaned data to a new file
    df.to_csv(output_file, index=False)
    print(f"\n[+] Success! Cleaned data saved at: {output_file}")
    print("[*] Now the data is ready for AI Training (Step 2)!")

except FileNotFoundError:
    print(f"[-] Error: '{input_file}' not found. Please check if the file is in the correct folder.")