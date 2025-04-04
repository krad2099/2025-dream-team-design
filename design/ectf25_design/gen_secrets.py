"""
Author: Dream Team
Date: 2025
Program: gen_secrets.py
"""

import os

def gen_secrets(channels: list[int]) -> bytes:
    """
    Generate the global secret shared between the Encoder and Decoder.
    TODO: Generate a secure 16-byte secret and write it to a file called "global.secrets"
          for provisioning. (Channel 0 is always valid and is not included in the list.)
    """
    secret = os.urandom(16)
    with open("/tmp/global.secrets", "wb") as f:
        f.write(secret)
    return secret
