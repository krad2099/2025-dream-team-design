import argparse
import json
from pathlib import Path
from OpenSSL import crypto

def gen_secrets(channels: list[int]) -> bytes:
    """Generate the contents of the secrets file

    :param channels: List of channel numbers that will be valid in this deployment.
    :returns: Contents of the secrets file
    """
    # Define the AES key for encryption (32-byte key for AES-256)
    aes_key = b"super_secure_key_32bytes_for_aes"
    key = aes_key

    # Encrypt some data using AES from OpenSSL (pyOpenSSL)
    data = b"secret data"
    cipher = crypto.Cipher('aes_256_cbc', key, iv=b'0123456789abcdef', mode=crypto.Cipher.MODE_CBC)
    encrypted_data = cipher.encrypt(data)

    # Create the secrets dictionary
    secrets = {
        "channels": channels,
        "some_secrets": encrypted_data,  # Store encrypted data (not plaintext)
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
        help="Supported channels. Channel 0 (broadcast) is always valid and will not"
        " be provided in this list",
    )
    return parser.parse_args()


def main():
    """Main function of gen_secrets"""
    args = parse_args()

    secrets = gen_secrets(args.channels)

    # Print the generated secrets for your own debugging
    # Attackers will NOT have access to the output of this (although they may have
    # subscriptions in certain scenarios), but feel free to remove
    #
    # NOTE: Printing sensitive data is generally not good security practice
    print(f"Generated secrets: {secrets}")

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        f.write(secrets)

    print(f"Wrote secrets to {str(args.secrets_file.absolute())}")


if __name__ == "__main__":
    main()
