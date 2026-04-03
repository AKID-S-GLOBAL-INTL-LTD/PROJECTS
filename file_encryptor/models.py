from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    salt = db.Column(db.String(64), nullable=False)
    
    def set_password(self, password):
        self.salt = base64.b64encode(os.urandom(16)).decode('utf-8')
        self.password_hash = generate_password_hash(
            password + self.salt, method='pbkdf2:sha256'
        )
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password + self.salt)
    
    def get_crypto_key(self):
        from flask import session
        raw_password = session.get('_crypto_password')
        if not raw_password:
            raise ValueError("No password in session – login again")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=base64.b64decode(self.salt),
            iterations=100000,
        )
        key = kdf.derive(raw_password.encode())
        return key