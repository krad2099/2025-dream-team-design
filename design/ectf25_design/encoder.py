import argparse
import struct
import json
import base64
import hmac
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class Encoder:
    def __init__(self, secrets: bytes):
        """Initialize encoder with secrets"""
        try:
            secrets = json.loads(secrets.decode())
        except json.JSONDecodeError:
            raise ValueError("Invalid secrets file: Ensure it is properly formatted JSON")

        master_key = secrets["master_key"].encode()

        # Use HKDF to derive separate AES and HMAC keys
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 32 bytes for AES, 32 bytes for HMAC
            salt=os.urandom(16),  # Random salt
            info=b"encryption_hmac",
            backend=default_backend()
        )
        derived_keys = hkdf.derive(master_key)
        self.hmac_key = derived_keys[32:]  # Last 32 bytes for HMAC key

        # Generate per-channel AES keys securely with random salts
        self.channel_keys = {
            ch: PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=os.urandom(16),  # Unique random salt per channel
                iterations=100000,
                backend=default_backend()
            ).derive(master_key)
            for ch in secrets["channels"]
        }

    def encrypt_frame(self, frame: bytes, key: bytes) -> bytes:
        """Encrypt the frame using AES-GCM with a random nonce"""
        nonce = os.urandom(12)  # Secure random nonce
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(frame) + encryptor.finalize()

        return nonce + encryptor.tag + ciphertext  # Prepend nonce & tag

    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        """Encode frame securely"""
        if channel not in self.channel_keys:
            raise ValueError("Invalid channel")

        key = self.channel_keys[channel]
        encrypted_frame = self.encrypt_frame(frame, key)

        # Compute HMAC for integrity check on the plaintext
        msg = struct.pack("<IQ", channel, timestamp) + frame  # HMAC applied to plaintext
        msg_hmac = hmac.new(self.hmac_key, msg, hashlib.sha256).digest()

        return encrypted_frame + msg_hmac  # Append HMAC after ciphertext


def main():
    parser = argparse.ArgumentParser(prog="encoder")
    parser.add_argument("secrets_file", type=argparse.FileType("rb"), help="Path to the secrets file")
    parser.add_argument("channel", type=int, help="Channel to encode for")
    parser.add_argument("frame", help="Contents of the frame")
    parser.add_argument("timestamp", type=int, help="64-bit timestamp")
    args = parser.parse_args()

    encoder = Encoder(args.secrets_file.read())

    encoded_data = encoder.encode(args.channel, args.frame.encode(), args.timestamp)

    # Print Base64-encoded output for easier handling
    print(base64.b64encode(encoded_data).decode())


if __name__ == "__main__":
    main()
