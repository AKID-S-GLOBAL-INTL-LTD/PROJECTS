from flask import Blueprint, render_template, jsonify
from db.models import LogModel
from core.engine import get_live_stats, get_live_feed

bp = Blueprint('dashboard', __name__)


@bp.route('/')
def index():
    return render_template('dashboard.html')


@bp.route('/api/stats')
def stats():
    db_stats = LogModel.stats()
    live = get_live_stats()
    return jsonify({**db_stats, 'uptime_seconds': live.get('total', 0), 'live': live})


@bp.route('/api/live')
def live():
    return jsonify(get_live_feed())
