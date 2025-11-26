#!/usr/bin/env python3
"""
CloudCrypt Bridge - Demo API
============================
Flask API wrapper for CloudCrypt Bridge encryption library.

⚠️  DEMO ONLY - NOT FOR PRODUCTION USE ⚠️

Endpoints:
    GET  /health   - Health check
    POST /encrypt  - Encrypt plaintext
    POST /decrypt  - Decrypt ciphertext
    POST /validate - Check if string is encrypted
    GET  /         - Demo frontend

Author: Mohan Iyer (mohan@pixels.net.nz)
Version: 1.0.0
"""

import os
import logging
from flask import Flask, request, jsonify, render_template

# Rate limiting
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    LIMITER_AVAILABLE = True
except ImportError:
    LIMITER_AVAILABLE = False

from cloudcrypt_bridge import SecretsManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Rate limiting (if available)
if LIMITER_AVAILABLE:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["100 per hour"]
    )
else:
    limiter = None
    logger.warning("Flask-Limiter not installed. Rate limiting disabled.")

# Initialize SecretsManager
DEMO_MODE = os.getenv('DEMO_MODE', 'true').lower() == 'true'
FERNET_KEY = os.getenv('FERNET_KEY')

if not FERNET_KEY:
    FERNET_KEY = 'demo-key-not-secure-32-chars!!'
    logger.warning("⚠️  Using demo FERNET_KEY - NOT SECURE FOR PRODUCTION")

try:
    manager = SecretsManager(master_key=FERNET_KEY)
except Exception as e:
    logger.error(f"Failed to initialize SecretsManager: {e}")
    manager = None


@app.route('/')
def index():
    """Serve demo frontend."""
    return render_template('index.html', demo_mode=DEMO_MODE)


@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "version": "1.0.0",
        "demo_mode": DEMO_MODE,
        "fernet_available": manager is not None,
        "rate_limiting": LIMITER_AVAILABLE,
        "warning": "DEMO ONLY - Do not use with real secrets" if DEMO_MODE else None
    })


@app.route('/encrypt', methods=['POST'])
def encrypt():
    """Encrypt plaintext string."""
    if not manager:
        return jsonify({"error": "SecretsManager not initialized", "success": False}), 500
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body must be JSON", "success": False}), 400
    
    plaintext = data.get('plaintext', '')
    if not plaintext:
        return jsonify({"error": "plaintext field is required", "success": False}), 400
    
    if len(plaintext) > 1024:
        return jsonify({"error": "plaintext exceeds maximum length (1024 bytes)", "success": False}), 400
    
    try:
        encrypted = manager.encrypt(plaintext)
        logger.info(f"Encrypted {len(plaintext)} chars -> {len(encrypted)} chars")
        
        return jsonify({
            "encrypted": encrypted,
            "success": True,
            "input_length": len(plaintext),
            "output_length": len(encrypted),
            "warning": "DEMO ONLY - Do not use for real secrets" if DEMO_MODE else None
        })
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        return jsonify({"error": str(e), "success": False}), 500


@app.route('/decrypt', methods=['POST'])
def decrypt():
    """Decrypt encrypted string."""
    if not manager:
        return jsonify({"error": "SecretsManager not initialized", "success": False}), 500
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body must be JSON", "success": False}), 400
    
    encrypted = data.get('encrypted', '')
    if not encrypted:
        return jsonify({"error": "encrypted field is required", "success": False}), 400
    
    try:
        plaintext = manager.decrypt(encrypted)
        is_valid = manager.validate_format(plaintext)
        logger.info(f"Decrypted {len(encrypted)} chars -> {len(plaintext)} chars (valid: {is_valid})")
        
        return jsonify({
            "plaintext": plaintext,
            "success": True,
            "format_valid": is_valid,
            "input_length": len(encrypted),
            "output_length": len(plaintext),
            "warning": "DEMO ONLY - Do not use for real secrets" if DEMO_MODE else None
        })
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return jsonify({"error": str(e), "success": False}), 500


@app.route('/validate', methods=['POST'])
def validate():
    """Check if a string appears to be encrypted."""
    if not manager:
        return jsonify({"error": "SecretsManager not initialized", "success": False}), 500
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body must be JSON", "success": False}), 400
    
    text = data.get('text', '')
    if not text:
        return jsonify({"error": "text field is required", "success": False}), 400
    
    is_encrypted = manager.is_encrypted(text)
    return jsonify({
        "is_encrypted": is_encrypted,
        "format": "fernet" if is_encrypted else "plaintext",
        "length": len(text),
        "success": True
    })


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Rate limit exceeded", "success": False, "retry_after": "60 seconds"}), 429


@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error", "success": False}), 500


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('DEBUG', 'false').lower() == 'true'
    
    print("=" * 60)
    print("CloudCrypt Bridge - Demo API")
    print("=" * 60)
    print(f"⚠️  DEMO MODE: {DEMO_MODE}")
    print(f"Port: {port}")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=port, debug=debug)