"""
Author: Dream Team
Date: 2025
Program: encoder.py
"""

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class Encoder:
    def __init__(self, secrets: bytes):
        # Derive a 16-byte key using HKDF with SHA-256.
        # Must use the same parameters ("decoder key" as context) as the decoder.
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b"decoder key",
        )
        self.key = hkdf.derive(secrets)
        self.aesgcm = AESGCM(self.key)
    
    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        # Generate a random 12-byte nonce (IV)
        nonce = os.urandom(12)
        # Encrypt the frame using AES-GCM with no additional authenticated data.
        # The output (ciphertext) includes the GCM tag.
        ciphertext = self.aesgcm.encrypt(nonce, frame, None)
        # Return the encoded frame as: [nonce (12 bytes)] || [ciphertext (frame length + tag)]
        return nonce + ciphertext
