from flask import Flask, render_template, request, jsonify
from subdomain_utils import discover
import threading
import uuid
import os

app = Flask(__name__)
app.secret_key = 'subdomain-discovery-secret'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max upload

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DEFAULT_WORDLIST = os.path.join('wordlists', 'subdomains.txt')
os.makedirs('wordlists', exist_ok=True)
if not os.path.exists(DEFAULT_WORDLIST):
    with open(DEFAULT_WORDLIST, 'w') as f:
        common = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
                  'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns', 'blog', 'pop3',
                  'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2', 'new', 'mysql', 'old',
                  'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta', 'shop', 'sql', 'secure',
                  'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 'email', 'images', 'img', 'download',
                  'dns', 'piwik', 'stats', 'portal', 'manage', 'start', 'info', 'apps', 'video', 'sip',
                  'dns2', 'api', 'cdn', 'cdn2', 'backup', 'git', 'go', 'shop2', 'erp', 'ftp2', 'remote',
                  'sms', 'voice', 'proxy', 'clock', 'live']
        f.write('\n'.join(common))

jobs = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/discover', methods=['POST'])
def start_discovery():
    domain = request.form.get('domain', '').strip().lower()
    if not domain:
        return jsonify({'error': 'Domain required'}), 400
    
    http_check = request.form.get('http_check') == 'on'
    max_subdomains = int(request.form.get('max_subdomains', 10000))
    custom_wordlist = request.files.get('wordlist')
    
    wordlist_path = DEFAULT_WORDLIST
    temp_wordlist_path = None
    if custom_wordlist and custom_wordlist.filename:
        temp_filename = f"{uuid.uuid4().hex}_{custom_wordlist.filename}"
        temp_wordlist_path = os.path.join(UPLOAD_FOLDER, temp_filename)
        custom_wordlist.save(temp_wordlist_path)
        wordlist_path = temp_wordlist_path
    
    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        'status': 'running',
        'results': [],
        'progress': {'total': 0, 'current': 0},
        'domain': domain,
        'temp_wordlist': temp_wordlist_path
    }
    
    def run_discovery():
        try:
            generator = discover(domain, wordlist_path, http_check=http_check, max_subdomains=max_subdomains)
            for update in generator:
                if update['type'] == 'progress':
                    jobs[job_id]['progress'] = {
                        'total': update['total'],
                        'current': update['current']
                    }
                elif update['type'] == 'result':
                    jobs[job_id]['results'].append(update['data'])
                elif update['type'] == 'error':
                    jobs[job_id]['status'] = 'error'
                    jobs[job_id]['error'] = update['message']
                    return
                elif update['type'] == 'done':
                    break
            jobs[job_id]['status'] = 'done'
        except Exception as e:
            jobs[job_id]['status'] = 'error'
            jobs[job_id]['error'] = str(e)
        finally:
            if jobs[job_id].get('temp_wordlist') and os.path.exists(jobs[job_id]['temp_wordlist']):
                try:
                    os.remove(jobs[job_id]['temp_wordlist'])
                except:
                    pass
    
    thread = threading.Thread(target=run_discovery)
    thread.daemon = True
    thread.start()
    
    return jsonify({'job_id': job_id, 'max_subdomains': max_subdomains})

@app.route('/status/<job_id>')
def status(job_id):
    if job_id not in jobs:
        return jsonify({'error': 'Invalid job'}), 404
    job = jobs[job_id]
    return jsonify({
        'status': job['status'],
        'progress': job.get('progress'),
        'results_count': len(job.get('results', [])),
        'error': job.get('error')
    })

@app.route('/results/<job_id>')
def results(job_id):
    if job_id not in jobs:
        return jsonify({'error': 'Invalid job'}), 404
    return jsonify({'results': jobs[job_id].get('results', [])})

if __name__ == '__main__':
    app.run(debug=True, port=5003)