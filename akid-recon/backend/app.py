from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from models import db, User, ScanHistory
from auth import auth_bp
from history import history_bp
from commands import generate_commands
import os

app = Flask(__name__, static_folder='../frontend', static_url_path='')
CORS(app)

# Config
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'akid-recon-secret-2026')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'akid-jwt-secret-2026')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///akid_recon.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
jwt = JWTManager(app)

app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(history_bp, url_prefix='/api/history')

@app.route('/api/generate', methods=['POST'])
def generate():
    from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
    data = request.get_json()
    domain = data.get('domain', '').strip().lower()
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    # Strip protocol if provided
    domain = domain.replace('https://', '').replace('http://', '').rstrip('/')
    commands = generate_commands(domain)
    # Save to history if authenticated
    user_id = None
    try:
        verify_jwt_in_request(optional=True)
        identity = get_jwt_identity()
        if identity:
            user_id = identity
            scan = ScanHistory(user_id=user_id, domain=domain)
            db.session.add(scan)
            db.session.commit()
    except Exception:
        pass
    return jsonify({'domain': domain, 'commands': commands, 'saved': user_id is not None})

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
