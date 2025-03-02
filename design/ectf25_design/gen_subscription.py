import argparse
import json
import struct
import hmac
import hashlib
import base64


def gen_subscription(secrets: bytes, device_id: int, start: int, end: int, channel: int) -> bytes:
    """
    Generate a secure subscription.

    :param secrets: Contents of the secrets file.
    :param device_id: Device ID of the Decoder.
    :param start: Subscription start timestamp.
    :param end: Subscription end timestamp.
    :param channel: Channel to enable.

    :returns: Securely generated subscription data.
    """
    # Load secrets securely
    secrets = json.loads(secrets.decode())
    master_key = secrets["master_key"].encode()

    # Derive per-channel key
    key = hashlib.pbkdf2_hmac("sha256", master_key, str(channel).encode(), 100000)

    # Create subscription data
    subscription_data = struct.pack("<IQQI", device_id, start, end, channel)

    # Compute HMAC for integrity
    msg_hmac = hmac.new(key, subscription_data, hashlib.sha256).digest()

    return subscription_data + msg_hmac


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", "-f", action="store_true", help="Force overwrite of subscription file")
    parser.add_argument("secrets_file", type=argparse.FileType("rb"), help="Path to secrets file")
    parser.add_argument("subscription_file", help="Output file for subscription data")
    parser.add_argument("device_id", type=lambda x: int(x, 0), help="Decoder device ID")
    parser.add_argument("start", type=lambda x: int(x, 0), help="Subscription start timestamp")
    parser.add_argument("end", type=int, help="Subscription end timestamp")
    parser.add_argument("channel", type=int, help="Channel to subscribe to")
    return parser.parse_args()


def main():
    args = parse_args()
    subscription = gen_subscription(args.secrets_file.read(), args.device_id, args.start, args.end, args.channel)

    with open(args.subscription_file, "wb" if args.force else "xb") as f:
        f.write(subscription)

    print(f"Subscription written to {args.subscription_file}")


if __name__ == "__main__":
    main()