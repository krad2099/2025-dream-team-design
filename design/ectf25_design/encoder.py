"""
Author: Dream Team
Date: 2025
Program: encoder.py
"""

import os
import time
import struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Constants matching decoder definitions
FRAME_SIZE = 64
SYNC_FRAME_CHANNEL = 0xFFFFFFFF

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
        # Generate a random 12-byte nonce (IV)
        nonce = os.urandom(12)
        # Encrypt the frame using AES-GCM with no additional authenticated data.
        ciphertext = self.aesgcm.encrypt(nonce, frame, None)
        encrypted_data = nonce + ciphertext
        # Pad encrypted_data to FRAME_SIZE bytes if necessary.
        if len(encrypted_data) < FRAME_SIZE:
            encrypted_data += bytes(FRAME_SIZE - len(encrypted_data))
        elif len(encrypted_data) > FRAME_SIZE:
            # If the encrypted data is too long, truncate it.
            encrypted_data = encrypted_data[:FRAME_SIZE]
        # Pack header: channel (4 bytes, little-endian) and timestamp (8 bytes, little-endian).
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
