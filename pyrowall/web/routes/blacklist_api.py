from flask import Blueprint, jsonify, request
from db.models import BlacklistModel
import ipaddress

bp = Blueprint('blacklist', __name__)


def valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        try:
            ipaddress.ip_network(ip, strict=False)
            return True
        except ValueError:
            return False


@bp.route('/api/blacklist', methods=['GET'])
def list_blacklist():
    return jsonify(BlacklistModel.all())


@bp.route('/api/blacklist', methods=['POST'])
def add_to_blacklist():
    data = request.json
    ip = data.get('ip_address', '').strip()
    reason = data.get('reason', '')

    if not ip:
        return jsonify({'error': 'ip_address is required'}), 400
    if not valid_ip(ip):
        return jsonify({'error': f'Invalid IP address: {ip}'}), 400

    success = BlacklistModel.add(ip, reason)
    if success:
        return jsonify({'message': f'{ip} added to blacklist'}), 201
    return jsonify({'error': 'IP already blacklisted or error occurred'}), 409


@bp.route('/api/blacklist/<int:entry_id>', methods=['DELETE'])
def remove_from_blacklist(entry_id):
    BlacklistModel.remove_by_id(entry_id)
    return jsonify({'message': 'Removed from blacklist'})


@bp.route('/api/blacklist/check/<ip>', methods=['GET'])
def check_ip(ip):
    return jsonify({'ip': ip, 'blacklisted': BlacklistModel.contains(ip)})
