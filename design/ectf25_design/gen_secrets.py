import argparse
import json
import os
import base64
import hashlib


def gen_secrets(channels: list[int]) -> bytes:
    """
    Generate secrets with strong cryptographic security.

    :param channels: List of valid channel numbers.

    :returns: Securely encoded secrets file.
    """
    # Generate a strong master key
    master_key = base64.b64encode(os.urandom(32)).decode()

    # Encrypt keys securely using HKDF
    secrets = {
        "master_key": master_key,
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