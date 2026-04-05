from flask import Blueprint, jsonify, request
from db.models import LogModel
import csv
import io

bp = Blueprint('logs', __name__)


@bp.route('/api/logs', methods=['GET'])
def get_logs():
    limit = min(int(request.args.get('limit', 200)), 1000)
    action = request.args.get('action', None)
    ip = request.args.get('ip', None)
    return jsonify(LogModel.recent(limit=limit, action_filter=action, ip_filter=ip))


@bp.route('/api/logs/export', methods=['GET'])
def export_logs():
    logs = LogModel.recent(limit=10000)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        'timestamp', 'action', 'src_ip', 'dst_ip',
        'src_port', 'dst_port', 'protocol', 'rule_name', 'size', 'flags'
    ])
    writer.writeheader()
    writer.writerows(logs)
    from flask import Response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=pyrowall_logs.csv'}
    )


@bp.route('/api/logs/clear', methods=['POST'])
def clear_logs():
    from db.database import get_connection
    with get_connection() as c:
        c.execute("DELETE FROM traffic_logs")
        c.commit()
    return jsonify({'message': 'Logs cleared'})
