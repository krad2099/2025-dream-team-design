import argparse
import json
from pathlib import Path
import ctypes
from loguru import logger

# Load the wolfSSL shared library using ctypes
wolfssl = ctypes.CDLL('/usr/local/lib/libwolfssl.dylib')  # Make sure to adjust this path

# Define the AES function signatures from wolfSSL
wolfssl.AES_set_encrypt_key.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
wolfssl.AES_set_encrypt_key.restype = ctypes.c_int

wolfssl.AES_encrypt.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
wolfssl.AES_encrypt.restype = ctypes.c_int

def gen_secrets(channels: list[int]) -> bytes:
    """Generate the contents of the secrets file

    :param channels: List of channel numbers that will be valid in this deployment.
    :returns: Contents of the secrets file
    """
    # Define the AES key for encryption (32-byte key for AES-256)
    aes_key = b"super_secure_key_32bytes_for_aes"
    key = (ctypes.c_ubyte * len(aes_key))(*aes_key)

    # Encrypt some data using AES from wolfSSL
    data = b"secret data"
    encrypted_data = (ctypes.c_ubyte * len(data))()
    
    # Set the AES key and encrypt the data
    wolfssl.AES_set_encrypt_key(key, len(aes_key))  # Set the key
    wolfssl.AES_encrypt(key, encrypted_data)  # Encrypt the data

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
    logger.debug(f"Generated secrets: {secrets}")

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        f.write(secrets)

    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")


if __name__ == "__main__":
    main()
