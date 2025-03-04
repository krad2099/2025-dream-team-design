import argparse
import json
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_secrets(num_channels: int, output_file: str):
    """Generates a secure secrets file with a master key and per-channel keys"""

    # Generate a random master key
    master_key = base64.b64encode(os.urandom(32)).decode()  # Store in Base64

    # Generate channel identifiers (e.g., 0 to num_channels-1)
    channels = list(range(num_channels))

    # Create and save the secrets JSON
    secrets = {
        "master_key": master_key,
        "channels": channels  # The actual keys will be derived later
    }

    with open(output_file, "w") as f:
        json.dump(secrets, f, indent=4)

    print(f"Secrets file generated: {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Generate a secrets JSON file.")
    parser.add_argument("num_channels", type=int, help="Number of channels to generate keys for")
    parser.add_argument("output_file", type=str, help="Path to save the secrets file")
    args = parser.parse_args()

    generate_secrets(args.num_channels, args.output_file)


if __name__ == "__main__":
    main()
