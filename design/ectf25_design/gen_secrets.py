import argparse
import json
from pathlib import Path
import hashlib  # Use hashlib for MD5

def gen_secrets(channels: list[int]) -> bytes:
    """Generate the contents of the secrets file

    :param channels: List of channel numbers that will be valid in this deployment.
    :returns: Contents of the secrets file
    """
    # Instead of using AES encryption, compute an MD5 digest of some secret data.
    secret_data = b"secret data"  # The secret data to hash
    md5 = hashlib.md5()
    md5.update(secret_data)
    # Use hexdigest() to get a 32-character hexadecimal string
    digest = md5.hexdigest()  # This is a string of 32 hex characters

    # Create the secrets dictionary. The "some_secrets" field now holds the MD5 hex digest.
    secrets = {
        "channels": channels,
        "some_secrets": digest,  # Store the MD5 hex digest as the secret
    }

    return json.dumps(secrets).encode()

def parse_args():
    """Define and parse the command line arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "channels",
        nargs="+",
        type=int,
        help="Supported channels. Channel 0 (broadcast) is always valid and will not be provided in this list",
    )
    return parser.parse_args()

def main():
    """Main function of gen_secrets"""
    args = parse_args()

    secrets = gen_secrets(args.channels)

    # For debugging; in production, you wouldn't print sensitive data
    print(f"Generated secrets: {secrets}")

    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        f.write(secrets)

    print(f"Wrote secrets to {str(args.secrets_file.absolute())}")

if __name__ == "__main__":
    main()
