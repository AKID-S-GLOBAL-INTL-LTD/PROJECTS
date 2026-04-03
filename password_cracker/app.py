from flask import Flask, render_template, request, jsonify, session
from cracker import identify_hash, crack_hash
import os
import threading
import time
import uuid

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024  # 2GB max upload

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs('wordlists', exist_ok=True)

# Store progress globally (in production use Redis/database)
progress_store = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/identify', methods=['POST'])
def identify():
    data = request.get_json()
    hash_string = data.get('hash', '')
    hash_type = identify_hash(hash_string)
    return jsonify({'type': hash_type})

@app.route('/crack', methods=['POST'])
def crack():
    target_hash = request.form.get('hash', '').strip()
    if not target_hash:
        return jsonify({'error': 'No hash provided'}), 400

    # Get user-selected hash type (or auto)
    selected_type = request.form.get('hash_type', 'auto')
    if selected_type == 'auto':
        hash_type = identify_hash(target_hash)
    else:
        hash_type = selected_type

    if hash_type == 'unknown':
        return jsonify({'error': 'Unknown hash format. Please select a type manually.'}), 400

    # Handle wordlist upload
    wordlist_path = None
    if 'wordlist' in request.files:
        file = request.files['wordlist']
        if file and file.filename:
            temp_filename = f"{uuid.uuid4().hex}_{file.filename}"
            wordlist_path = os.path.join(UPLOAD_FOLDER, temp_filename)
            file.save(wordlist_path)

    if not wordlist_path:
        # Use default common.txt
        default_wordlist = os.path.join('wordlists', 'common.txt')
        if not os.path.exists(default_wordlist):
            # Create a minimal default wordlist if missing
            with open(default_wordlist, 'w') as f:
                f.write('\n'.join(['password', '123456', 'admin', 'letmein', 'welcome']))
        wordlist_path = default_wordlist

    # Start cracking in background thread
    job_id = str(int(time.time())) + '_' + uuid.uuid4().hex[:6]
    progress_store[job_id] = {
        'status': 'running',
        'attempts': 0,
        'found': False,
        'hash_type': hash_type
    }

    def crack_task():
        def update_progress(attempts, word):
            progress_store[job_id]['attempts'] = attempts

        password, attempts, elapsed = crack_hash(
            target_hash, wordlist_path, hash_type, update_progress
        )
        progress_store[job_id]['status'] = 'done'
        progress_store[job_id]['password'] = password
        progress_store[job_id]['attempts'] = attempts
        progress_store[job_id]['elapsed'] = elapsed
        # Clean up uploaded wordlist if it was a temp file
        if wordlist_path and wordlist_path.startswith(UPLOAD_FOLDER):
            try:
                os.remove(wordlist_path)
            except:
                pass

    thread = threading.Thread(target=crack_task)
    thread.daemon = True
    thread.start()

    return jsonify({
        'job_id': job_id,
        'hash_type': hash_type,
        'message': 'Cracking started'
    })

@app.route('/progress/<job_id>')
def progress(job_id):
    if job_id not in progress_store:
        return jsonify({'error': 'Invalid job'}), 404
    data = progress_store[job_id]
    if data['status'] == 'done':
        return jsonify({
            'status': 'done',
            'found': data['password'] is not None,
            'password': data['password'],
            'attempts': data['attempts'],
            'time_seconds': round(data['elapsed'], 3),
            'hash_type': data.get('hash_type', 'unknown'),
            'attempts_per_sec': round(data['attempts'] / data['elapsed'], 2) if data['elapsed'] > 0 else 0
        })
    else:
        return jsonify({
            'status': 'running',
            'attempts': data['attempts']
        })

if __name__ == '__main__':
    app.run(debug=True, port=5002)