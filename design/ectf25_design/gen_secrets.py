"""
Author: Dream Team
Date: 2025
Program: gen_secrets.py
"""

import os

def gen_secrets(channels: list[int]) -> bytes:
    """
    Generate the global secret shared between the Encoder and Decoder.
    (Channel 0 is always valid and is not included in the list.)
    """
    secret = os.urandom(16)
    # Provision the secret by writing it to a file for the decoder to load.
    with open("global.secrets", "wb") as f:
        f.write(secret)
    return secret
