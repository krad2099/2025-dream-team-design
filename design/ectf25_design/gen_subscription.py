"""
Author: Dream Team
Date: 2025
Program: gen_subscription.py
"""

import struct

def gen_subscription(secrets: bytes, device_id: int, start: int, end: int, channel: int) -> bytes:
    """
    Generate a subscription update for a given device and channel.
    
    This function packs the provided parameters into a binary structure 
    (little-endian) in the following order:
      - device_id (32 bits)
      - start timestamp (64 bits)
      - end timestamp (64 bits)
      - channel (32 bits)
      
    The resulting 24-byte output is returned.
    
    In a more advanced design, you might include a MAC or other authentication
    data. However, because the decoder expects a fixed 24-byte structure, we are
    keeping the output size unchanged.
    """
    return struct.pack("<IQQI", device_id, start, end, channel)
