import os
import math

def is_suspicious(file_path):
    """Basic heuristic checks for suspicious files."""
    try:
        # Only check regular files
        if not os.path.isfile(file_path):
            return False

        # 1. File extension check
        suspicious_ext = ['.exe', '.bat', '.bin', '.sh', '.js', '.vbs', '.scr']
        if any(file_path.lower().endswith(ext) for ext in suspicious_ext):
            return True

        # 2. Check file size (example: very small or very large files)
        size = os.path.getsize(file_path)
        if size < 1024 or size > 100 * 1024 * 1024:  # <1KB or >100MB
            return True

        # 3. Entropy check (high entropy = packed/encrypted)
        with open(file_path, 'rb') as f:
            data = f.read()
            if len(data) == 0:
                return False
            entropy = -sum([(data.count(byte)/len(data)) * math.log2(data.count(byte)/len(data)) 
                            for byte in set(data)])
            if entropy > 7.5:  # threshold, tweakable
                return True

        return False

    except Exception as e:
        # If any error occurs reading the file, mark as suspicious
        return True
