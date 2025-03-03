import argparse
import struct
import json
import base64
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Encoder:
    def __init__(self, secrets: bytes):
        """Initialize encoder with secrets"""
        secrets = json.loads(secrets.decode())

        # Generate per-channel AES keys securely
        self.channel_keys = {
            ch: PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=str(ch).encode(),
                iterations=100000,
                backend=default_backend()
            ).derive(secrets["master_key"].encode())
            for ch in secrets["channels"]
        }

        # HMAC key for integrity verification
        self.hmac_key = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"hmac",
            iterations=100000,
            backend=default_backend()
        ).derive(secrets["master_key"].encode())

    def encrypt_frame(self, frame: bytes, key: bytes) -> bytes:
        """Encrypt the frame using AES-GCM"""
        nonce = b"\x00" * 12  # Fixed nonce for testing; should be random in production
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(frame) + encryptor.finalize()
        return nonce + encryptor.tag + ciphertext

    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        """Encode frame securely"""
        if channel not in self.channel_keys:
            raise ValueError("Invalid channel")

        key = self.channel_keys[channel]
        encrypted_frame = self.encrypt_frame(frame, key)

        # Compute HMAC for integrity
        msg = struct.pack("<IQ", channel, timestamp) + encrypted_frame
        msg_hmac = hmac.new(self.hmac_key, msg, hashlib.sha256).digest()

        return msg + msg_hmac


def main():
    parser = argparse.ArgumentParser(prog="encoder")
    parser.add_argument("secrets_file", type=argparse.FileType("rb"), help="Path to the secrets file")
    parser.add_argument("channel", type=int, help="Channel to encode for")
    parser.add_argument("frame", help="Contents of the frame")
    parser.add_argument("timestamp", type=int, help="64-bit timestamp")
    args = parser.parse_args()

    encoder = Encoder(args.secrets_file.read())
    print(repr(encoder.encode(args.channel, args.frame.encode(), args.timestamp)))


if __name__ == "__main__":
    main()
