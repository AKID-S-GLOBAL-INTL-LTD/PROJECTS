from flask import Flask, render_template, request, jsonify
from cracker import identify_hash, crack_hash, brute_force
import os

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max wordlist

# Default wordlist path (you can replace with a larger one)
DEFAULT_WORDLIST = 'wordlists/common.txt'

# Ensure wordlist directory exists
os.makedirs('wordlists', exist_ok=True)
# Create a small default wordlist if not exists
if not os.path.exists(DEFAULT_WORDLIST):
    with open(DEFAULT_WORDLIST, 'w') as f:
        common = ['password', '123456', 'admin', 'letmein', 'welcome', 'monkey', 'dragon', 'baseball', 'master', 'sunshine']
        f.write('\n'.join(common))

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
    attack_type = request.form.get('attack_type', 'dictionary')
    hash_type = identify_hash(target_hash)
    
    if hash_type == 'unknown':
        return jsonify({'error': 'Unknown hash format'}), 400
    
    # Handle custom wordlist upload
    wordlist_path = DEFAULT_WORDLIST
    if 'wordlist' in request.files:
        file = request.files['wordlist']
        if file and file.filename:
            temp_path = 'wordlists/uploaded.txt'
            file.save(temp_path)
            wordlist_path = temp_path
    
    max_words = int(request.form.get('max_words', 10000))
    
    if attack_type == 'dictionary':
        password, attempts, elapsed = crack_hash(target_hash, wordlist_path, hash_type, max_words)
    elif attack_type == 'bruteforce':
        max_len = int(request.form.get('max_length', 4))
        charset = request.form.get('charset', 'abcdefghijklmnopqrstuvwxyz0123456789')
        password, attempts, elapsed = brute_force(target_hash, hash_type, max_len, charset)
    else:
        return jsonify({'error': 'Invalid attack type'}), 400
    
    # Clean up uploaded wordlist
    if 'wordlist' in request.files and wordlist_path != DEFAULT_WORDLIST:
        try:
            os.remove(wordlist_path)
        except:
            pass
    
    return jsonify({
        'found': password is not None,
        'password': password,
        'attempts': attempts,
        'time_seconds': round(elapsed, 3),
        'hash_type': hash_type,
        'attempts_per_sec': round(attempts / elapsed, 2) if elapsed > 0 else 0
    })

if __name__ == '__main__':
    app.run(debug=True, port=5002)