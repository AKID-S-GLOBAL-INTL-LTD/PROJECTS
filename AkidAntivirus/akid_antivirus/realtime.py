import time, os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from akid_detector.scanner import scan_directory
from akid_detector.signatures import load_signatures
from akid_antivirus.quarantine import quarantine_file

class MonitorHandler(FileSystemEventHandler):
    def __init__(self, signatures):
        self.signatures = signatures

    def on_created(self, event):
        if not event.is_directory:
            infected = scan_directory(os.path.dirname(event.src_path), self.signatures)
            for f, t in infected:
                quarantine_file(f)

def start_monitoring(folders):
    signatures = load_signatures("database/malware_signatures.csv")
    event_handler = MonitorHandler(signatures)
    observer = Observer()
    for folder in folders:
        observer.schedule(event_handler, folder, recursive=True)
    observer.start()
    print("[*] Real-time protection started.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
