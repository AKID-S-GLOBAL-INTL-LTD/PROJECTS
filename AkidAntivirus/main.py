import sys, os
from akid_detector.signatures import load_signatures
from akid_detector.scanner import scan_directory
from akid_antivirus.quarantine import quarantine_file
from akid_antivirus.realtime import start_monitoring
from colorama import Fore, Style
from tabulate import tabulate

def banner():
    os.system("clear")
    print(Fore.CYAN + "="*50)
    print(Fore.CYAN + "      AKID ANTIVIRUS – PRO EDITION")
    print(Fore.CYAN + "="*50 + Style.RESET_ALL)

def show_commands():
    commands = [
        ["scan <folder>", "Scan folder immediately"],
        ["monitor <folder(s)>", "Start real-time protection"],
        ["quarantine", "List quarantined files"],
        ["logs", "View scan & detection logs"]
    ]
    print(tabulate(commands, headers=["Command", "Description"], tablefmt="fancy_grid"))

def view_quarantine():
    folder = "quarantine"
    files = os.listdir(folder) if os.path.exists(folder) else []
    if files:
        table = [[i+1, f] for i, f in enumerate(files)]
        print(tabulate(table, headers=["#", "File"], tablefmt="fancy_grid"))
    else:
        print(Fore.GREEN + "Quarantine is empty." + Style.RESET_ALL)

def main():
    banner()
    if len(sys.argv) < 2:
        show_commands()
        sys.exit()
    cmd = sys.argv[1].lower()
    if cmd == "scan":
        if len(sys.argv) < 3:
            print("Please specify folder to scan.")
            sys.exit()
        folder = sys.argv[2]
        sigs = load_signatures("database/malware_signatures.csv")
        infected = scan_directory(folder, sigs)
        for f, t in infected:
            action = input(f"Quarantine {f}? (y/n): ").lower()
            if action == "y":
                quarantine_file(f)
    elif cmd == "monitor":
        if len(sys.argv) < 3:
            print("Please specify folder(s) to monitor.")
            sys.exit()
        folders = sys.argv[2:]
        start_monitoring(folders)
    elif cmd == "quarantine":
        view_quarantine()
    elif cmd == "logs":
        log_file = "akid_logs.txt"
        if os.path.exists(log_file):
            with open(log_file) as f:
                print(f.read())
        else:
            print("No logs found.")
    else:
        print("Unknown command.")
        show_commands()

if __name__ == "__main__":
    main()
