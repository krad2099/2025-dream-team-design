"""
Author: Dream Team
Date: 2025
Program: gen_secrets.py
"""

import os

def gen_secrets(channels: list[int]) -> bytes:
    """
    Generate the global secrets that are passed to both the Encoder and Decoder.
    (Channel 0 is always valid and is not included in the list.)
    """
    return os.urandom(16)
