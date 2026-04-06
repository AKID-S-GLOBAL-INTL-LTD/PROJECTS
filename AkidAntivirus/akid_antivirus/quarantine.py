import shutil, os
def quarantine_file(file_path):
    quarantine_folder = "quarantine"
    if not os.path.exists(quarantine_folder):
        os.makedirs(quarantine_folder)
    filename = os.path.basename(file_path)
    dest = os.path.join(quarantine_folder, filename)
    shutil.move(file_path, dest)
    print(f"[+] File quarantined: {filename}")
