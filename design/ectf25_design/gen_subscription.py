"""
Author: Dream Team
Date: 2025
Program: gen_subscription.py
"""

import struct

def gen_subscription(secrets: bytes, device_id: int, start: int, end: int, channel: int) -> bytes:
    """
    Generate a subscription update for a given device and channel.
    """
    return struct.pack("<IQQI", device_id, start, end, channel)
