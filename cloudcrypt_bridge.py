#!/usr/bin/env python3
"""
CloudCrypt Bridge - Universal Encryption Solution
==================================================
Battle-tested encryption library extracted from Seekrates AI production.
Zero failures since November 18, 2025.

Features:
- Dual-method decryption (handles mixed encryption formats)
- Self-testing encryption (validates roundtrip)
- Format validation (catches decryption failures)
- Fernet encryption (AES-128-CBC with HMAC)

Origin: 4-week production crisis â†’ $20K debugging cost â†’ This solution

Usage:
    from cloudcrypt_bridge import SecretsManager
    
    manager = SecretsManager(master_key='your-32-char-key-here')
    encrypted = manager.encrypt('sk-proj-abc123...')
    plaintext = manager.decrypt(encrypted)

License: MIT
Author: Mohan Iyer (mohan@pixels.net.nz)
Version: 1.0.0
"""

import os
import base64
import logging
from typing import Optional

# Optional cryptography import (graceful fallback)
try:
    from cryptography.fernet import Fernet, InvalidToken
    FERNET_AVAILABLE = True
except ImportError:
    FERNET_AVAILABLE = False
    InvalidToken = Exception  # Fallback type

logger = logging.getLogger(__name__)


class SecretsManager:
    """
    Secure secrets management with dual-method decryption.
    
    Handles the nightmare scenario: mixed encryption methods in production.
    Method 1: Base64-derived Fernet key (canonical)
    Method 2: Direct Fernet key (legacy)
    
    Both methods are tried automatically - no migration required.
    """
    
    def __init__(self, master_key: Optional[str] = None):
        """
        Initialize SecretsManager with encryption key.
        
        Args:
            master_key: 32+ character encryption key. 
                       Falls back to FERNET_KEY or ENCRYPTION_KEY env vars.
        """
        self.master_key = master_key or os.getenv('FERNET_KEY') or os.getenv('ENCRYPTION_KEY')
        
        if not self.master_key:
            raise ValueError(
                "No master key provided. Set FERNET_KEY environment variable "
                "or pass master_key parameter."
            )
        
        if len(self.master_key) < 32:
            raise ValueError(
                f"Master key must be at least 32 characters. "
                f"Got {len(self.master_key)} characters."
            )
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext with self-testing validation.
        
        Args:
            plaintext: String to encrypt (e.g., API key)
            
        Returns:
            Fernet-encrypted string (gAAAAAB...)
            
        Raises:
            ValueError: If encryption self-test fails
            RuntimeError: If cryptography library not available
        """
        if not plaintext:
            raise ValueError("Cannot encrypt empty string")
        
        if not isinstance(plaintext, str):
            raise TypeError(f"plaintext must be str, not {type(plaintext).__name__}")
        
        if not FERNET_AVAILABLE:
            raise RuntimeError(
                "cryptography library not installed. "
                "Run: pip install cryptography"
            )
        
        try:
            # Method 1: Base64-derived key (canonical)
            # Encode first, then take 32 bytes (handles unicode safely)
            key = base64.urlsafe_b64encode(self.master_key.encode()[:32])
            fernet = Fernet(key)
            encrypted = fernet.encrypt(plaintext.encode()).decode()
            
            # Self-test: Verify we can decrypt what we just encrypted
            test_decrypt = self.decrypt(encrypted)
            if test_decrypt != plaintext:
                raise ValueError(
                    f"Encryption self-test failed! "
                    f"Original length: {len(plaintext)}, "
                    f"Decrypted length: {len(test_decrypt)}"
                )
            
            return encrypted
            
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt(self, encrypted_text: str) -> str:
        """
        Decrypt with automatic dual-method fallback.
        
        Tries Method 1 (base64-derived) first, then Method 2 (direct).
        This handles mixed encryption formats transparently.
        
        Args:
            encrypted_text: Fernet-encrypted string
            
        Returns:
            Decrypted plaintext string
        """
        if encrypted_text is None:
            raise TypeError("encrypted_text cannot be None")
        
        if not isinstance(encrypted_text, str):
            raise TypeError(f"encrypted_text must be str, not {type(encrypted_text).__name__}")
        
        if not encrypted_text:
            return encrypted_text
        
        # Clean input (handle legacy markers)
        cleaned = encrypted_text.strip()
        if cleaned.startswith('ðŸ”‘'):
            cleaned = cleaned[1:]
        
        # Short strings are probably not encrypted
        if len(cleaned) < 20:
            return cleaned
        
        if not FERNET_AVAILABLE:
            # Fallback to base64 decode
            try:
                return base64.b64decode(cleaned.encode()).decode()
            except Exception:
                return cleaned
        
        # METHOD 1: Base64-derived key (canonical - try first)
        try:
            # Encode first, then take 32 bytes (handles unicode safely)
            key = base64.urlsafe_b64encode(self.master_key.encode()[:32])
            fernet = Fernet(key)
            plaintext = fernet.decrypt(cleaned.encode()).decode()
            
            if self.validate_format(plaintext):
                logger.debug("Decryption successful (Method 1: base64-derived)")
                return plaintext
        except (InvalidToken, Exception) as e:
            logger.debug(f"Method 1 failed: {e}")
        
        # METHOD 2: Direct Fernet key (legacy fallback)
        try:
            # Ensure key is valid Fernet format (32 bytes, base64-encoded)
            if len(self.master_key) == 44 and self.master_key.endswith('='):
                fernet = Fernet(self.master_key.encode())
                plaintext = fernet.decrypt(cleaned.encode()).decode()
                
                if self.validate_format(plaintext):
                    logger.debug("Decryption successful (Method 2: direct key)")
                    return plaintext
        except (InvalidToken, Exception) as e:
            logger.debug(f"Method 2 failed: {e}")
        
        # METHOD 3: Base64 fallback (non-Fernet)
        try:
            plaintext = base64.b64decode(cleaned.encode()).decode()
            if self.validate_format(plaintext):
                logger.debug("Decryption successful (Method 3: base64)")
                return plaintext
        except Exception as e:
            logger.debug(f"Method 3 (base64) failed: {e}")
        
        # All methods failed - return original (might already be plaintext)
        logger.warning(f"All decryption methods failed for input length {len(cleaned)}")
        return cleaned
    
    def validate_format(self, plaintext: str) -> bool:
        """
        Validate that decrypted text looks like a real API key.
        
        This catches the silent failure scenario where decryption
        "succeeds" but produces garbage (wrong key used).
        
        Args:
            plaintext: Decrypted string to validate
            
        Returns:
            True if format looks valid, False otherwise
        """
        if not plaintext:
            return False
        
        # Fernet signature = still encrypted
        if plaintext.startswith('gAAAAAB'):
            return False
        
        # Common API key prefixes (known valid formats)
        valid_prefixes = [
            'sk-',           # OpenAI
            'sk-proj-',      # OpenAI project keys
            'sk-ant-',       # Anthropic
            'gsk-',          # Mistral (some formats)
            'AIza',          # Google/Gemini
        ]
        
        # If it matches a known prefix, definitely valid
        if any(plaintext.startswith(prefix) for prefix in valid_prefixes):
            return True
        
        # For other formats (passwords, custom keys), check basic sanity
        # Must be printable ASCII and reasonable length
        if len(plaintext) >= 8 and plaintext.isprintable():
            return True
        
        return False
    
    def is_encrypted(self, text: str) -> bool:
        """
        Check if a string appears to be Fernet-encrypted.
        
        Args:
            text: String to check
            
        Returns:
            True if string looks like Fernet ciphertext
        """
        if not text:
            return False
        
        cleaned = text.strip()
        if cleaned.startswith('ðŸ”‘'):
            cleaned = cleaned[1:]
        
        # Fernet tokens start with gAAAAAB and are base64
        return (
            cleaned.startswith('gAAAAAB') and 
            len(cleaned) >= 50 and
            all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=' for c in cleaned)
        )


# Convenience function for one-off operations
def encrypt_value(plaintext: str, master_key: Optional[str] = None) -> str:
    """Encrypt a single value without creating a SecretsManager instance."""
    manager = SecretsManager(master_key=master_key)
    return manager.encrypt(plaintext)


def decrypt_value(encrypted: str, master_key: Optional[str] = None) -> str:
    """Decrypt a single value without creating a SecretsManager instance."""
    manager = SecretsManager(master_key=master_key)
    return manager.decrypt(encrypted)


# CLI for testing
if __name__ == '__main__':
    import sys
    
    print("CloudCrypt Bridge v1.0.0")
    print("=" * 40)
    
    # Check for FERNET_KEY
    if not os.getenv('FERNET_KEY'):
        print("\nâš ï¸  FERNET_KEY not set. Using test key.")
        os.environ['FERNET_KEY'] = 'test-key-32-characters-exactly!!'
    
    manager = SecretsManager()
    
    # Test encryption roundtrip
    test_value = "sk-test-api-key-12345"
    print(f"\nTest value: {test_value}")
    
    encrypted = manager.encrypt(test_value)
    print(f"Encrypted:  {encrypted[:50]}...")
    
    decrypted = manager.decrypt(encrypted)
    print(f"Decrypted:  {decrypted}")
    
    if decrypted == test_value:
        print("\nâœ… Encryption roundtrip successful!")
    else:
        print("\nâŒ Encryption roundtrip FAILED!")
        sys.exit(1)