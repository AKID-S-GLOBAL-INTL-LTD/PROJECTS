"""Flask application factory."""

from flask import Flask
from flask_socketio import SocketIO

socketio = SocketIO()


def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')
    app.config['SECRET_KEY'] = 'pyrowall-dev-secret'

    socketio.init_app(app, cors_allowed_origins='*', async_mode='threading')

    # Register blueprints
    from web.routes.dashboard import bp as dashboard_bp
    from web.routes.rules_api import bp as rules_bp
    from web.routes.blacklist_api import bp as blacklist_bp
    from web.routes.logs_api import bp as logs_bp
    from web.routes.settings_api import bp as settings_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(rules_bp)
    app.register_blueprint(blacklist_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(settings_bp)

    return app
