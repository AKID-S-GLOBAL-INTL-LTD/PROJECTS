#!/usr/bin/env python3
"""
AKID's Firewall App - Cross-platform Firewall with Web Dashboard
Run with: sudo python3 main.py  (Linux)
          python3 main.py       (Windows, as Administrator)
"""

import sys
import os
import threading
import logging
import platform

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db.database import init_db
from core.rules import seed_default_rules
from core.engine import PacketEngine
from web.app import create_app

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger('akid_firewall')


def check_privileges():
    """Check if running with required privileges."""
    if platform.system() == 'Windows':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            log.error("AKID's Firewall App requires Administrator privileges on Windows.")
            log.error("Please right-click and 'Run as Administrator'.")
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            log.error("AKID's Firewall App requires root privileges on Linux.")
            log.error("Please run: sudo python3 main.py")
            sys.exit(1)


def main():
    print("""
╔═══════════════════════════════════════════╗
║       AKID'S Firewall App v1.0            ║
║   Cross-platform Network Security Tool   ║
╚═══════════════════════════════════════════╝
""")

    check_privileges()

    # Initialize database
    log.info("Initializing database...")
    init_db()
    seed_default_rules()

    # Create Flask app
    app = create_app()

    # Start packet engine in background thread
    engine = PacketEngine()
    engine_thread = threading.Thread(target=engine.start, daemon=True, name="PacketEngine")
    engine_thread.start()
    log.info("Packet inspection engine started.")

    # Start web dashboard
    log.info("Starting web dashboard at http://127.0.0.1:5000")
    print("\n  Dashboard: http://127.0.0.1:5000\n")

    from flask_socketio import SocketIO
    socketio = SocketIO(app)

    # Store engine reference for routes
    app.config['ENGINE'] = engine

    try:
        socketio.run(app, host='127.0.0.1', port=5000, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        log.info("Shutting down AKID's Firewall App...")
        engine.stop()
        sys.exit(0)


if __name__ == '__main__':
    main()
