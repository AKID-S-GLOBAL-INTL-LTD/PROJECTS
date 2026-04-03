from flask import Flask, render_template, request, jsonify
import re
import hashlib
import requests
from math import log2

app = Flask(__name__)

def calculate_entropy(password):
    if not password:
        return 0
    freq = {}
    for c in password:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0
    length = len(password)
    for count in freq.values():
        p = count / length
        entropy -= p * log2(p)
    return entropy * length

def check_breach_pwned(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code != 200:
            return None
        for line in resp.text.splitlines():
            if line.split(':')[0] == suffix:
                return int(line.split(':')[1])
        return 0
    except:
        return None

def estimate_crack_time(entropy):
    if entropy <= 0:
        return 0
    return 2 ** entropy / 1e9

def strength_analysis(password):
    if not password:
        return {"score": 0, "entropy": 0, "breaches": 0, "crack_time_seconds": 0, "suggestions": ["Enter a password"]}
    
    score = 0
    suggestions = []
    
    if len(password) >= 12:
        score += 1
    elif len(password) >= 8:
        score += 0.5
    else:
        suggestions.append("Use at least 8 characters (12+ is better)")
    
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[^A-Za-z0-9]', password))
    complexity_score = sum([has_upper, has_lower, has_digit, has_special])
    score += complexity_score / 4
    
    if complexity_score < 3:
        suggestions.append("Mix uppercase, lowercase, numbers, and symbols")
    
    entropy = calculate_entropy(password)
    if entropy >= 60:
        score += 1
    elif entropy >= 40:
        score += 0.5
    if entropy < 40:
        suggestions.append("Avoid common patterns and repetitions")
    
    breach_count = check_breach_pwned(password)
    if breach_count is None:
        breach_display = -1
    else:
        breach_display = breach_count
        if breach_count > 0:
            suggestions.append(f"⚠️ Found in {breach_count} data breaches – do NOT use!")
            score = 0
    
    score = min(max(score, 0), 4)
    crack_time = estimate_crack_time(entropy)
    
    return {
        "score": round(score, 1),
        "entropy": round(entropy, 1),
        "breaches": breach_display,
        "crack_time_seconds": crack_time,
        "suggestions": suggestions[:3]
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():
    data = request.get_json()
    password = data.get('password', '')
    return jsonify(strength_analysis(password))

if __name__ == '__main__':
    app.run(debug=True, port=5001)  # different port than encryption tool