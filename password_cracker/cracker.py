import hashlib
import re
import time
import bcrypt
import struct

# ---------- Pure Python MD4 implementation (for NTLM) ----------
def md4(data):
    """MD4 hash function - pure Python implementation"""
    def left_rotate(x, n):
        return ((x << n) & 0xffffffff) | (x >> (32 - n))
    
    # Initial state
    h0, h1, h2, h3 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    
    # Pre-processing: append bit '1' and padding zeros
    ml = len(data) * 8
    data += b'\x80'
    while (len(data) * 8) % 512 != 448:
        data += b'\x00'
    data += struct.pack('<Q', ml)  # append length in bits
    
    # Process each 512-bit chunk
    for offset in range(0, len(data), 64):
        chunk = data[offset:offset+64]
        w = list(struct.unpack('<16I', chunk))
        
        a, b, c, d = h0, h1, h2, h3
        
        # Round 1
        for i in range(16):
            k = i
            if i == 0: f = (b & c) | (~b & d)
            elif i == 1: f = (b & c) | (~b & d)
            elif i == 2: f = (b & c) | (~b & d)
            else: f = (b & c) | (~b & d)
            a, b, c, d = d, left_rotate((a + f + w[k]) & 0xffffffff, 3), b, c
        
        # Round 2
        for i in range(16):
            k = (i % 16)
            if i == 0: f = (b & c) | (b & d) | (c & d)
            elif i == 1: f = (b & c) | (b & d) | (c & d)
            elif i == 2: f = (b & c) | (b & d) | (c & d)
            else: f = (b & c) | (b & d) | (c & d)
            a, b, c, d = d, left_rotate((a + f + w[k] + 0x5a827999) & 0xffffffff, 3), b, c
        
        # Round 3
        for i in range(16):
            k = (i % 16)
            if i == 0: f = b ^ c ^ d
            elif i == 1: f = b ^ c ^ d
            elif i == 2: f = b ^ c ^ d
            else: f = b ^ c ^ d
            a, b, c, d = d, left_rotate((a + f + w[k] + 0x6ed9eba1) & 0xffffffff, 3), b, c
        
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
    
    return struct.pack('<4I', h0, h1, h2, h3).hex()

def ntlm_hash(password):
    """Calculate NTLM hash of a password (MD4 of UTF-16LE)"""
    password_utf16 = password.encode('utf-16le')
    return md4(password_utf16)

def identify_hash(hash_string):
    """Return hash type based on length and format"""
    hash_string = hash_string.strip()
    length = len(hash_string)
    
    if hash_string.startswith('$2b$') or hash_string.startswith('$2a$') or hash_string.startswith('$2y$'):
        return 'bcrypt'
    if re.match(r'^[0-9A-Fa-f]{32}$', hash_string):
        return 'NTLM'
    if length == 32 and re.match(r'^[0-9a-f]{32}$', hash_string):
        return 'MD5'
    if length == 40 and re.match(r'^[0-9a-f]{40}$', hash_string):
        return 'SHA1'
    if length == 64 and re.match(r'^[0-9a-f]{64}$', hash_string):
        return 'SHA256'
    if length == 128 and re.match(r'^[0-9a-f]{128}$', hash_string):
        return 'SHA512'
    return 'unknown'

def hash_password(password, algo):
    """Hash a password using the specified algorithm"""
    if algo == 'MD5':
        return hashlib.md5(password.encode()).hexdigest()
    elif algo == 'SHA1':
        return hashlib.sha1(password.encode()).hexdigest()
    elif algo == 'SHA256':
        return hashlib.sha256(password.encode()).hexdigest()
    elif algo == 'SHA512':
        return hashlib.sha512(password.encode()).hexdigest()
    elif algo == 'NTLM':
        return ntlm_hash(password)
    else:
        raise ValueError(f"Unsupported algorithm: {algo}")

def crack_hash(target_hash, wordlist_path, hash_type, max_words=10000):
    """Dictionary attack"""
    if hash_type == 'bcrypt':
        return crack_bcrypt(target_hash, wordlist_path, max_words)
    
    start_time = time.time()
    attempts = 0
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, word in enumerate(f):
                if i >= max_words:
                    break
                word = word.strip()
                if not word:
                    continue
                attempts += 1
                hashed = hash_password(word, hash_type)
                if hashed == target_hash.lower():
                    elapsed = time.time() - start_time
                    return (word, attempts, elapsed)
    except FileNotFoundError:
        return (None, 0, 0)
    elapsed = time.time() - start_time
    return (None, attempts, elapsed)

def crack_bcrypt(target_hash, wordlist_path, max_words):
    start_time = time.time()
    attempts = 0
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, word in enumerate(f):
                if i >= max_words:
                    break
                word = word.strip()
                if not word:
                    continue
                attempts += 1
                if bcrypt.checkpw(word.encode(), target_hash.encode()):
                    elapsed = time.time() - start_time
                    return (word, attempts, elapsed)
    except FileNotFoundError:
        return (None, 0, 0)
    elapsed = time.time() - start_time
    return (None, attempts, elapsed)

def brute_force(target_hash, hash_type, max_length=4, charset='abcdefghijklmnopqrstuvwxyz0123456789'):
    from itertools import product
    start_time = time.time()
    attempts = 0
    
    for length in range(1, max_length + 1):
        for combo in product(charset, repeat=length):
            attempts += 1
            candidate = ''.join(combo)
            if hash_type == 'bcrypt':
                if bcrypt.checkpw(candidate.encode(), target_hash.encode()):
                    elapsed = time.time() - start_time
                    return (candidate, attempts, elapsed)
            else:
                hashed = hash_password(candidate, hash_type)
                if hashed == target_hash.lower():
                    elapsed = time.time() - start_time
                    return (candidate, attempts, elapsed)
            if attempts > 500000:
                elapsed = time.time() - start_time
                return (None, attempts, elapsed)
    elapsed = time.time() - start_time
    return (None, attempts, elapsed)