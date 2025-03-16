"""
Author: Dream Team
Date: 2025
Program: encoder.py
"""

import os
import time
import struct
import hashlib

# Use a simple XOR cipher – no external crypto library needed.
# Constants matching our decoder definitions.
FRAME_SIZE = 64
SYNC_FRAME_CHANNEL = 0xFFFFFFFF
KEY_SIZE = 16

class Encoder:
    def __init__(self, secrets: bytes):
        # Simplified key derivation: hash the secret with SHA-256 and take the first 16 bytes.
        self.key = hashlib.sha256(secrets).digest()[:KEY_SIZE]
    
    def get_monotonic_timestamp(self) -> int:
        """Returns a monotonic timestamp in nanoseconds."""
        return time.monotonic_ns()
    
    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        """
        Encodes a normal frame packet.
        The frame packet format:
          - channel: 4 bytes (little-endian)
          - timestamp: 8 bytes (little-endian)
          - data: FRAME_SIZE bytes (XOR-encrypted frame data)
        The encryption is a simple XOR of the 64-byte plaintext with the key.
        """
        if len(frame) != 64:
            raise ValueError(f"Expected plaintext frame to be 64 bytes, got {len(frame)} bytes")
        # Perform XOR encryption.
        encrypted_data = bytes([frame[i] ^ self.key[i % KEY_SIZE] for i in range(64)])
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
