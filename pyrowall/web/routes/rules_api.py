from flask import Blueprint, jsonify, request
from db.models import RuleModel

bp = Blueprint('rules', __name__)


@bp.route('/api/rules', methods=['GET'])
def list_rules():
    return jsonify(RuleModel.all())


@bp.route('/api/rules', methods=['POST'])
def create_rule():
    data = request.json
    required = ['name', 'action']
    for f in required:
        if not data.get(f):
            return jsonify({'error': f'Missing field: {f}'}), 400

    rule = {
        'name':        data.get('name', ''),
        'description': data.get('description', ''),
        'action':      data.get('action', 'block'),
        'protocol':    data.get('protocol', 'any'),
        'direction':   data.get('direction', 'both'),
        'src_ip':      data.get('src_ip', 'any') or 'any',
        'dst_ip':      data.get('dst_ip', 'any') or 'any',
        'src_port':    data.get('src_port', 'any') or 'any',
        'dst_port':    data.get('dst_port', 'any') or 'any',
        'is_default':  0,
        'enabled':     1,
        'priority':    int(data.get('priority', 100)),
    }
    rule_id = RuleModel.create(rule)
    return jsonify({'id': rule_id, 'message': 'Rule created'}), 201


@bp.route('/api/rules/<int:rule_id>', methods=['PUT'])
def update_rule(rule_id):
    data = request.json
    existing = RuleModel.get(rule_id)
    if not existing:
        return jsonify({'error': 'Rule not found'}), 404

    rule = {
        'name':        data.get('name', existing['name']),
        'description': data.get('description', existing['description']),
        'action':      data.get('action', existing['action']),
        'protocol':    data.get('protocol', existing['protocol']),
        'direction':   data.get('direction', existing['direction']),
        'src_ip':      data.get('src_ip', existing['src_ip']) or 'any',
        'dst_ip':      data.get('dst_ip', existing['dst_ip']) or 'any',
        'src_port':    data.get('src_port', existing['src_port']) or 'any',
        'dst_port':    data.get('dst_port', existing['dst_port']) or 'any',
        'enabled':     data.get('enabled', existing['enabled']),
        'priority':    int(data.get('priority', existing['priority'])),
    }
    RuleModel.update(rule_id, rule)
    return jsonify({'message': 'Rule updated'})


@bp.route('/api/rules/<int:rule_id>', methods=['DELETE'])
def delete_rule(rule_id):
    existing = RuleModel.get(rule_id)
    if not existing:
        return jsonify({'error': 'Rule not found'}), 404
    if existing.get('is_default'):
        return jsonify({'error': 'Cannot delete default rules'}), 403
    RuleModel.delete(rule_id)
    return jsonify({'message': 'Rule deleted'})


@bp.route('/api/rules/<int:rule_id>/toggle', methods=['POST'])
def toggle_rule(rule_id):
    existing = RuleModel.get(rule_id)
    if not existing:
        return jsonify({'error': 'Rule not found'}), 404
    RuleModel.toggle(rule_id)
    updated = RuleModel.get(rule_id)
    return jsonify({'enabled': bool(updated['enabled'])})
