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
ENCODER_PORT = 5000

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
def start_encoder_server():
    """
    Starts a TCP server that listens for encoding requests.
    """
    host = "localhost"
    port = ENCODER_PORT
    encoder = Encoder()

    print(f"[INFO] Encoder Server starting on {host}:{port}...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"[INFO] Encoder Server listening on {host}:{port}")

        while True:
            conn, addr = server_socket.accept()
            with conn:
                print(f"[INFO] Connection established with {addr}")
                try:
                    data = conn.recv(1024)
                    if not data:
                        print("[WARNING] No data received, closing connection.")
                        continue
                    
                    # Expecting: channel (4 bytes) | timestamp (8 bytes) | frame (remaining bytes)
                    if len(data) < 12:
                        print("[ERROR] Received invalid frame, ignoring request.")
                        continue

                    channel, timestamp = struct.unpack('<IQ', data[:12])
                    frame = data[12:]

                    print(f"[INFO] Encoding frame for channel {channel} at timestamp {timestamp}")

                    # Encode the frame
                    encoded_frame = encoder.encode(channel, frame, timestamp)

                    # Send back the encoded frame
                    conn.sendall(encoded_frame)
                except Exception as e:
                    print(f"[ERROR] Encoding error: {e}")

if __name__ == "__main__":
    start_encoder_server()
