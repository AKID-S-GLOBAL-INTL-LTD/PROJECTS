from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, ScanHistory

history_bp = Blueprint('history', __name__)

@history_bp.route('/', methods=['GET'])
@jwt_required()
def get_history():
    user_id = get_jwt_identity()
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    scans = ScanHistory.query.filter_by(user_id=user_id)\
        .order_by(ScanHistory.scanned_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({
        'scans': [s.to_dict() for s in scans.items],
        'total': scans.total,
        'pages': scans.pages,
        'current_page': page
    })

@history_bp.route('/<int:scan_id>', methods=['DELETE'])
@jwt_required()
def delete_scan(scan_id):
    user_id = get_jwt_identity()
    scan = ScanHistory.query.filter_by(id=scan_id, user_id=user_id).first()
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    db.session.delete(scan)
    db.session.commit()
    return jsonify({'message': 'Deleted'})

@history_bp.route('/clear', methods=['DELETE'])
@jwt_required()
def clear_history():
    user_id = get_jwt_identity()
    ScanHistory.query.filter_by(user_id=user_id).delete()
    db.session.commit()
    return jsonify({'message': 'History cleared'})
