from flask import Blueprint, jsonify, request
from db.models import SettingsModel
import psutil
import platform

bp = Blueprint('settings', __name__)


@bp.route('/api/settings', methods=['GET'])
def get_settings():
    return jsonify(SettingsModel.all())


@bp.route('/api/settings', methods=['POST'])
def update_settings():
    data = request.json
    allowed = ['engine_enabled', 'log_allowed', 'log_blocked', 'interface', 'max_log_entries']
    for key, value in data.items():
        if key in allowed:
            SettingsModel.set(key, value)
    return jsonify({'message': 'Settings updated'})


@bp.route('/api/system', methods=['GET'])
def system_info():
    """Return system info for the dashboard."""
    try:
        net_io = psutil.net_io_counters()
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()

        # Get network interfaces
        interfaces = []
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family.name in ('AF_INET',):
                    interfaces.append({'name': name, 'ip': addr.address})

        return jsonify({
            'platform':   platform.system(),
            'hostname':   platform.node(),
            'cpu_pct':    cpu,
            'mem_pct':    mem.percent,
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'interfaces': interfaces,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
