import os
from akid_detector.hashing import hash_file
LOG_FILE = "akid_malware_logs.txt"

def log_event(message):
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} | {message}\n")

def is_suspicious(file_path):
    filename = os.path.basename(file_path)
    suspicious_locations = ["/tmp", "/var/tmp"]
    suspicious_ext = [".exe", ".sh", ".bin", ".js", ".vbs", ".scr"]
    if file_path.startswith(tuple(suspicious_locations)) and filename.endswith(tuple(suspicious_ext)):
        return True
    if filename.startswith(".") and os.path.expanduser("~") in file_path:
        return True
    return False

def scan_directory(directory, signatures):
    infected_files = []
    safe_count = 0
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            threat = None
            try:
                file_hash = hash_file(file_path)
            except:
                continue  # skip unreadable files

            if file_hash in signatures:
                threat = signatures[file_hash]
                infected_files.append((file_path, threat))
                print(f"[!] {file_path} -> {threat}")
                log_event(f"{file_path} | Malware detected -> {threat}")

            elif is_suspicious(file_path):
                threat = "Suspicious – Heuristic"
                infected_files.append((file_path, threat))
                print(f"[!] {file_path} -> {threat}")
                log_event(f"{file_path} | Suspicious file -> Heuristic")

            else:
                safe_count += 1
                print(f"[OK] {file_path}")
                log_event(f"{file_path} | Safe")

    # Summary
    print("\n=== Scan Summary ===")
    print(f"Total files scanned: {safe_count + len(infected_files)}")
    print(f"Malware detected: {len([f for f in infected_files if 'Malware' in f[1]])}")
    print(f"Suspicious files: {len([f for f in infected_files if 'Suspicious' in f[1]])}")
    print(f"Detailed log: {os.path.abspath(LOG_FILE)}")
    print("====================\n")

    return infected_files
