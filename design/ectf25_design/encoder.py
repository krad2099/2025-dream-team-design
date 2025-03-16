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

# Constants matching decoder definitions
FRAME_SIZE = 92
SYNC_FRAME_CHANNEL = 0xFFFFFFFF

class Encoder:
    def __init__(self):
        # Load the secret directly from the global.secrets file.
        try:
            with open("global.secrets", "rb") as f:
                secrets = f.read(16)
                if len(secrets) != 16:
                    raise ValueError("global.secrets file must be exactly 16 bytes.")
        except Exception as e:
            raise RuntimeError("Failed to load global.secrets: " + str(e))
        
        # Simplified key derivation: hash the secret with SHA-256 and take the first 16 bytes.
        self.key = hashlib.sha256(secrets).digest()[:16]
        self.aesgcm = AESGCM(self.key)
    
    def get_monotonic_timestamp(self) -> int:
        """Returns a monotonic timestamp in nanoseconds."""
        return time.monotonic_ns()
    
    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        """
        Encodes a normal frame packet.
        The frame packet format:
          - channel: 4 bytes (little-endian)
          - timestamp: 8 bytes (little-endian)
          - data: FRAME_SIZE bytes (encrypted frame data, padded if necessary)
        The encrypted frame data is computed as: nonce (12 bytes) || ciphertext.
        """
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, frame, None)
        encrypted_data = nonce + ciphertext
        if len(encrypted_data) < FRAME_SIZE:
            encrypted_data += bytes(FRAME_SIZE - len(encrypted_data))
        elif len(encrypted_data) > FRAME_SIZE:
            encrypted_data = encrypted_data[:FRAME_SIZE]
        header = struct.pack('<IQ', channel, timestamp)
        return header + encrypted_data

    def create_sync_frame(self) -> bytes:
        """
        Creates a sync frame packet used to synchronize clocks.
        The sync frame uses the SYNC_FRAME_CHANNEL and a monotonic timestamp.
        The data field is filled with zeros.
        """
        timestamp = self.get_monotonic_timestamp()
        data = bytes(FRAME_SIZE)
        header = struct.pack('<IQ', SYNC_FRAME_CHANNEL, timestamp)
        return header + data
