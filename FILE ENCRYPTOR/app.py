import os
from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from flask_login import LoginManager, login_required, current_user
from werkzeug.utils import secure_filename
from models import db, User
from auth import auth_bp
from crypto_utils import encrypt_file_stream, decrypt_file_stream
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ENCRYPTED_FOLDER'] = 'encrypted'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['ENCRYPTED_FOLDER'], exist_ok=True)

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

app.register_blueprint(auth_bp, url_prefix='/auth')

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
@login_required
def encrypt():
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('index'))
    file = request.files['file']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('index'))
    
    algorithm = request.form.get('algorithm', 'aes')
    original_filename = secure_filename(file.filename)
    unique_id = str(uuid.uuid4())
    temp_input = os.path.join(app.config['UPLOAD_FOLDER'], f"{unique_id}_{original_filename}")
    file.save(temp_input)
    
    encrypted_name = f"{unique_id}_{original_filename}.enc"
    encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], encrypted_name)
    
    # Derive a key from user's password (simplified – in production, use a derived key stored per user)
    key = current_user.get_crypto_key()   # We'll implement this in models.py
    
    encrypt_file_stream(temp_input, encrypted_path, key, algorithm)
    os.remove(temp_input)
    
    flash(f'File encrypted with {algorithm.upper()}')
    return send_file(encrypted_path, as_attachment=True, download_name=f"{original_filename}.enc")

@app.route('/decrypt', methods=['POST'])
@login_required
def decrypt():
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('index'))
    file = request.files['file']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('index'))
    
    # Expect .enc file – algorithm auto-detected from metadata
    original_filename = secure_filename(file.filename)
    unique_id = str(uuid.uuid4())
    temp_input = os.path.join(app.config['UPLOAD_FOLDER'], f"{unique_id}_{original_filename}")
    file.save(temp_input)
    
    # Decrypt to a temp file
    temp_output = os.path.join(app.config['UPLOAD_FOLDER'], f"{unique_id}_decrypted")
    key = current_user.get_crypto_key()
    
    try:
        decrypt_file_stream(temp_input, temp_output, key)
        # Return the decrypted file
        return send_file(temp_output, as_attachment=True, download_name=original_filename.replace('.enc', ''))
    except Exception as e:
        flash(f'Decryption failed: {str(e)}')
        return redirect(url_for('index'))
    finally:
        if os.path.exists(temp_input):
            os.remove(temp_input)
        if os.path.exists(temp_output):
            os.remove(temp_output)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)