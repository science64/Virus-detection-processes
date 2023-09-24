import hashlib
import requests
import psutil
import json
import os

api_key = '' # VirusTotal API key, just register and optain free API key

# Whitelist file location
whitelist_file = 'whitelist.txt'

def load_whitelist():
    try:
        if os.path.exists(whitelist_file):
            with open(whitelist_file, 'r') as f:
                return json.load(f)
    except json.JSONDecodeError:
        # Return an empty dictionary if the file is empty or not valid JSON
        return {}
    return {}

def save_to_whitelist(whitelist):
    with open(whitelist_file, 'w') as f:
        json.dump(whitelist, f)

def get_virustotal_report(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    return response

# Load the whitelist
whitelist = load_whitelist()

# Set to keep track of already processed file paths
processed_paths = set()

# Iterate over all running processes
for proc in psutil.process_iter(attrs=['pid', 'name', 'exe']):
    try:
        process_info = proc.info
        file_path = process_info['exe']

        if not file_path:
            print(f"Executable path not available for {process_info['name']} (PID: {process_info['pid']}).")
            continue  # Skip if the executable path is not available

        # Check if the process is in the whitelist or has already been processed
        if file_path in whitelist or file_path in processed_paths:
            print(f"{file_path} (PID: {process_info['pid']}) is in the whitelist or already processed. Skipping...")
            continue

        # Add the file path to the set of processed paths
        processed_paths.add(file_path)

        # Calculate the SHA-256 hash of the file
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        # Get the VirusTotal report
        response = get_virustotal_report(file_hash)

        if response.status_code == 200:
            report = response.json()
            total_engines = report['data']['attributes']['last_analysis_stats']['malicious'] + \
                            report['data']['attributes']['last_analysis_stats']['undetected']
            malicious_engines = report['data']['attributes']['last_analysis_stats']['malicious']
            print(f"{file_path} (PID: {process_info['pid']}) was scanned by {total_engines} antivirus engines.")

            if malicious_engines == 0:
                # If not detected as malicious, add to the whitelist
                whitelist[file_path] = {
                    'name': process_info['name'],
                    'pid': process_info['pid'],
                }
                save_to_whitelist(whitelist)
                print(f"{file_path} (PID: {process_info['pid']}) added to the whitelist.")
            else:
                print(f"{malicious_engines} engines detected this file as malicious.")
                if malicious_engines > 2:
                    print("DANGER! DANGER! More than 2 antivirus engines detected this file as malicious.")
        else:
            print(
                f"{file_path} (PID: {process_info['pid']}) was not in VirusTotal's dataset or an error occurred. Response Code: {response.status_code}")

    except (psutil.NoSuchProcess, FileNotFoundError, PermissionError) as e:
        # Handle exceptions, e.g., if the process has ended or the file is not accessible
        print(f"Could not process {process_info.get('name', 'N/A')} (PID: {process_info.get('pid', 'N/A')}): {e}")