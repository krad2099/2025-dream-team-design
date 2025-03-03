import argparse
import json
import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def derive_key(master_key: bytes, salt: bytes) -> bytes:
    """Derives a secure 32-byte AES key from a master key using PBKDF2-HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(master_key)


def gen_secrets(channels: list[int]) -> bytes:
    """
    Generate secrets with strong cryptographic security.

    :param channels: List of valid channel numbers.

    :returns: Securely encoded secrets file.
    """
    master_key = os.urandom(32)

    secrets = {
        "master_key": base64.b64encode(master_key).decode(),
        "channels": channels
    }

    return json.dumps(secrets).encode()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", "-f", action="store_true", help="Force overwrite of secrets file")
    parser.add_argument("secrets_file", help="Path to the secrets file")
    parser.add_argument("channels", nargs="+", type=int, help="Supported channels")
    return parser.parse_args()


def main():
    args = parse_args()
    secrets = gen_secrets(args.channels)

    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        f.write(secrets)

    print(f"Secrets written to {args.secrets_file}")


if __name__ == "__main__":
    main()
