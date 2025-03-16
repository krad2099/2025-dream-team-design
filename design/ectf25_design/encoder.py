"""
Author: Dream Team
Date: 2025
Program: encoder.py
"""

import os
import time
import struct
import hashlib

# Constants matching decoder definitions
FRAME_SIZE = 92
SYNC_FRAME_CHANNEL = 0xFFFFFFFF
KEY_SIZE = 16
GCM_IV_SIZE = 12
GCM_TAG_SIZE = 16
PLAINTEXT_SIZE = 64  # Plaintext frame must be 64 bytes

class Encoder:
    def __init__(self, secrets: bytes):
        # Simple key derivation: hash the secret with SHA-256 and take the first 16 bytes.
        self.key = hashlib.sha256(secrets).digest()[:KEY_SIZE]
    
    def get_monotonic_timestamp(self) -> int:
        """Returns a monotonic timestamp in nanoseconds."""
        return time.monotonic_ns()
    
    def xor_encrypt(self, plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
        # Encrypt plaintext using XOR: 
        # ciphertext[i] = plaintext[i] XOR key[i mod KEY_SIZE] XOR nonce[i mod 12]
        result = bytearray()
        for i in range(len(plaintext)):
            result.append(plaintext[i] ^ key[i % len(key)] ^ nonce[i % len(nonce)])
        return bytes(result)
    
    def compute_tag(self, data: bytes) -> bytes:
        # Simple tag: sum all bytes mod 256, repeated to fill 16 bytes.
        s = sum(data) & 0xFF
        return bytes([s] * GCM_TAG_SIZE)
    
    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        """
        Encodes a normal frame packet.
        The packet format is:
          - channel: 4 bytes (little-endian)
          - timestamp: 8 bytes (little-endian)
          - data: FRAME_SIZE bytes (encrypted frame data)
        
        The encrypted frame data is constructed as:
          [nonce (12 bytes)] || [ciphertext (64 bytes)] || [tag (16 bytes)]
        """
        # Ensure the plaintext frame is exactly 64 bytes.
        if len(frame) != PLAINTEXT_SIZE:
            if len(frame) < PLAINTEXT_SIZE:
                frame = frame.ljust(PLAINTEXT_SIZE, b'\0')
            else:
                frame = frame[:PLAINTEXT_SIZE]
        
        # Generate a random nonce (IV) of 12 bytes.
        nonce = os.urandom(GCM_IV_SIZE)
        # Encrypt the plaintext using XOR encryption.
        ciphertext = self.xor_encrypt(frame, self.key, nonce)
        # Compute a simple tag over (nonce || ciphertext).
        tag = self.compute_tag(nonce + ciphertext)
        # Build the encrypted data: nonce || ciphertext || tag.
        encrypted_data = nonce + ciphertext + tag  # Total length: 12+64+16 = 92 bytes.
        header = struct.pack('<IQ', channel, timestamp)
        return header + encrypted_data

    def create_sync_frame(self) -> bytes:
        """
        Creates a sync frame packet used to synchronize clocks.
        The sync frame uses SYNC_FRAME_CHANNEL and a monotonic timestamp.
        The data field is filled with zeros.
        """
        timestamp = self.get_monotonic_timestamp()
        data = bytes(FRAME_SIZE)
        header = struct.pack('<IQ', SYNC_FRAME_CHANNEL, timestamp)
        return header + data
