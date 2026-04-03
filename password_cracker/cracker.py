import hashlib
import re
import time
import bcrypt
import struct

# ---------- MD4 implementation (same as before) ----------
def md4(data):
    def left_rotate(x, n):
        return ((x << n) & 0xffffffff) | (x >> (32 - n))
    h0, h1, h2, h3 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    ml = len(data) * 8
    data += b'\x80'
    while (len(data) * 8) % 512 != 448:
        data += b'\x00'
    data += struct.pack('<Q', ml)
    for offset in range(0, len(data), 64):
        chunk = data[offset:offset+64]
        w = list(struct.unpack('<16I', chunk))
        a, b, c, d = h0, h1, h2, h3
        # Round 1
        for i in range(16):
            k = i
            f = (b & c) | (~b & d)
            a, b, c, d = d, left_rotate((a + f + w[k]) & 0xffffffff, 3), b, c
        # Round 2
        for i in range(16):
            k = i % 16
            f = (b & c) | (b & d) | (c & d)
            a, b, c, d = d, left_rotate((a + f + w[k] + 0x5a827999) & 0xffffffff, 3), b, c
        # Round 3
        for i in range(16):
            k = i % 16
            f = b ^ c ^ d
            a, b, c, d = d, left_rotate((a + f + w[k] + 0x6ed9eba1) & 0xffffffff, 3), b, c
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
    return struct.pack('<4I', h0, h1, h2, h3).hex()

def ntlm_hash(password):
    return md4(password.encode('utf-16le'))

def identify_hash(hash_string):
    """Return hash type based on length and format (prioritize common ones)"""
    h = hash_string.strip()
    if h.startswith('$2b$') or h.startswith('$2a$') or h.startswith('$2y$'):
        return 'bcrypt'
    length = len(h)
    if length == 32 and re.match(r'^[0-9a-f]{32}$', h):
        return 'MD5'          # lowercase hex -> MD5 (most common)
    if length == 32 and re.match(r'^[0-9A-F]{32}$', h):
        return 'NTLM'         # uppercase hex -> NTLM (common in Windows)
    if length == 32 and re.match(r'^[0-9A-Fa-f]{32}$', h):
        # mixed case – could be either; default to MD5 for compatibility
        return 'MD5'
    if length == 40 and re.match(r'^[0-9a-f]{40}$', h):
        return 'SHA1'
    if length == 64 and re.match(r'^[0-9a-f]{64}$', h):
        return 'SHA256'
    if length == 128 and re.match(r'^[0-9a-f]{128}$', h):
        return 'SHA512'
    return 'unknown'

def hash_password(password, algo):
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

def crack_hash(target_hash, wordlist_path, hash_type, progress_callback=None):
    """
    Dictionary attack with optional progress callback.
    progress_callback(attempts, current_word) - called every 1000 attempts.
    """
    if hash_type == 'bcrypt':
        return crack_bcrypt(target_hash, wordlist_path, progress_callback)
    
    start_time = time.time()
    attempts = 0
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for word in f:
                word = word.strip()
                if not word:
                    continue
                attempts += 1
                hashed = hash_password(word, hash_type)
                if hashed == target_hash.lower():
                    elapsed = time.time() - start_time
                    return (word, attempts, elapsed)
                if progress_callback and attempts % 1000 == 0:
                    progress_callback(attempts, word)
    except FileNotFoundError:
        return (None, 0, 0)
    elapsed = time.time() - start_time
    return (None, attempts, elapsed)

def crack_bcrypt(target_hash, wordlist_path, progress_callback=None):
    start_time = time.time()
    attempts = 0
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for word in f:
                word = word.strip()
                if not word:
                    continue
                attempts += 1
                if bcrypt.checkpw(word.encode(), target_hash.encode()):
                    elapsed = time.time() - start_time
                    return (word, attempts, elapsed)
                if progress_callback and attempts % 1000 == 0:
                    progress_callback(attempts, word)
    except FileNotFoundError:
        return (None, 0, 0)
    elapsed = time.time() - start_time
    return (None, attempts, elapsed)