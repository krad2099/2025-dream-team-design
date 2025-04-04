"""
Author: Dream Team
Date: 2025
Program: encoder.py
"""

import os
import time
import struct
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Constants matching decoder definitions.
# For a 64-byte plaintext, the encrypted data will be:
#   12 (nonce) + 64 (plaintext) + 16 (tag) = 92 bytes.
DEFAULT_PLAINTEXT_SIZE = 64
SYNC_FRAME_CHANNEL = 0xFFFFFFFF

class Encoder:
    def __init__(self, secret: bytes = None):
        """
        Initialize the Encoder.
        TODO: If no secret is provided, load the global secret from file 'global.secrets'.
              If the file does not exist, generate a new secret using gen_secrets.
        """
        if secret is None:
            try:
                with open("global.secrets", "rb") as f:
                    secret = f.read()
            except FileNotFoundError:
                from gen_secrets import gen_secrets
                secret = gen_secrets([])
        # Simplified key derivation: hash the secret with SHA-256 and take the first 16 bytes.
        self.key = hashlib.sha256(secret).digest()[:16]
        self.aesgcm = AESGCM(self.key)
    
    def get_monotonic_timestamp(self) -> int:
        """Returns a monotonic timestamp in nanoseconds."""
        return time.monotonic_ns()
    
    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        """
        Encodes a normal frame packet.
        
        The frame packet format is:
          - channel: 4 bytes (little-endian)
          - timestamp: 8 bytes (little-endian)
          - data: encrypted frame data
        
        The encrypted frame data is computed as:
          [nonce (12 bytes)] || [ciphertext (plaintext + auth tag (16 bytes))]
        
        The caller should provide a frame of up to 64 bytes.
        """
        # Generate a random 12-byte nonce.
        nonce = os.urandom(12)
        # Encrypt the frame; AESGCM.encrypt returns ciphertext with auth tag appended.
        ciphertext = self.aesgcm.encrypt(nonce, frame, None)
        # Concatenate nonce and ciphertext to form the encrypted data.
        encrypted_data = nonce + ciphertext
        # Pack header: channel (4 bytes) and timestamp (8 bytes) in little-endian.
        header = struct.pack('<IQ', channel, timestamp)
        return header + encrypted_data

    def create_sync_frame(self) -> bytes:
        """
        Creates a sync frame packet used to synchronize clocks.
        
        The sync frame uses the SYNC_FRAME_CHANNEL and a monotonic timestamp.
        The data field is filled with zeros to match the length of a normal encrypted frame.
        """
        timestamp = self.get_monotonic_timestamp()
        # Calculate the expected encrypted data length:
        # nonce (12) + DEFAULT_PLAINTEXT_SIZE + tag (16)
        encrypted_data_length = 12 + DEFAULT_PLAINTEXT_SIZE + 16
        data = bytes(encrypted_data_length)
        header = struct.pack('<IQ', SYNC_FRAME_CHANNEL, timestamp)
        return header + data
