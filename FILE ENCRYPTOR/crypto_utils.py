import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

def encrypt_file_stream(input_path, output_path, key, algorithm='aes'):
    """
    Encrypt a file in chunks (supports huge files).
    Stores: nonce + ciphertext + tag
    For ChaCha20: nonce (12 bytes) + ciphertext
    """
    if algorithm == 'aes':
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
            fout.write(nonce)   # 12 bytes
            # Stream in 64KB chunks
            while True:
                chunk = fin.read(64 * 1024)
                if not chunk:
                    break
                encrypted_chunk = encryptor.update(chunk)
                fout.write(encrypted_chunk)
            # Finalize and write tag (16 bytes)
            encryptor.finalize()
            fout.write(encryptor.tag)
    
    elif algorithm == 'chacha':
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
            fout.write(nonce)
            while True:
                chunk = fin.read(64 * 1024)
                if not chunk:
                    break
                encrypted_chunk = encryptor.update(chunk)
                fout.write(encrypted_chunk)
            encryptor.finalize()
    else:
        raise ValueError("Unsupported algorithm")

def decrypt_file_stream(input_path, output_path, key):
    """
    Auto-detect algorithm by checking file length and trying AES-GCM first.
    Assumes first 12 bytes = nonce, last 16 bytes = tag for AES.
    For ChaCha20, there is no tag.
    """
    with open(input_path, 'rb') as fin:
        nonce = fin.read(12)
        # Peek at file size to guess algorithm
        fin.seek(0, os.SEEK_END)
        file_size = fin.tell()
        fin.seek(12)
        
        # Try AES-GCM first (requires tag at end)
        if file_size > 12 + 16:  # at least nonce + tag + 1 byte
            fin.seek(-16, os.SEEK_END)
            tag = fin.read(16)
            ciphertext_size = file_size - 12 - 16
            fin.seek(12)
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            with open(output_path, 'wb') as fout:
                remaining = ciphertext_size
                while remaining > 0:
                    chunk = fin.read(min(64 * 1024, remaining))
                    if not chunk:
                        break
                    decrypted = decryptor.update(chunk)
                    fout.write(decrypted)
                    remaining -= len(chunk)
                decryptor.finalize()
            return
    
    # If not AES (or failed), try ChaCha20 (no tag)
    fin.seek(12)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    with open(output_path, 'wb') as fout:
        while True:
            chunk = fin.read(64 * 1024)
            if not chunk:
                break
            decrypted = decryptor.update(chunk)
            fout.write(decrypted)
        decryptor.finalize()