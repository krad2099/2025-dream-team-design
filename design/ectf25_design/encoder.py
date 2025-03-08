import argparse
import struct
import json
import hashlib  # Using Python's standard hashlib for MD5

class Encoder:
    def __init__(self, secrets: bytes):
        """
        You **may not** change the arguments or returns of this function!

        :param secrets: Contents of the secrets file generated by
            ectf25_design.gen_secrets
        """
        # Load the json of the secrets file
        secrets = json.loads(secrets)

        # Load the example secrets for use in Encoder.encode
        self.some_secrets = secrets["some_secrets"]

        # The key is still stored but will not be used with MD5.
        self.key = b"super_secure_key_32bytes_for_aes"  # Not used with MD5

    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        """The frame encoder function using MD5 only.

        Instead of encrypting the frame, this version computes an MD5 hash of the frame.

        :param channel: 16b unsigned channel number. Channel 0 is the emergency
            broadcast that must be decodable by all channels.
        :param frame: Frame to encode. Max frame size is 64 bytes.
        :param timestamp: 64b timestamp to use for encoding. **NOTE**: This value may
            have no relation to the current timestamp, so you should not compare it
            against the current time. The timestamp is guaranteed to strictly
            monotonically increase (always go up) with subsequent calls to encode.

        :returns: The encoded frame, which consists of the channel, timestamp, and MD5 digest of the frame.
        """
        # Compute MD5 hash of the frame data
        md5 = hashlib.md5()
        md5.update(frame)
        digest = md5.digest()  # 16-byte MD5 hash

        # Pack the channel (32-bit unsigned) and timestamp (64-bit unsigned)
        header = struct.pack("<IQ", channel, timestamp)
        # Append the MD5 digest to the header
        return header + digest

def main():
    """A test main to one-shot encode a frame"""
    parser = argparse.ArgumentParser(prog="ectf25_design.encoder")
    parser.add_argument(
        "secrets_file", type=argparse.FileType("rb"), help="Path to the secrets file"
    )
    parser.add_argument("channel", type=int, help="Channel to encode for")
    parser.add_argument("frame", help="Contents of the frame")
    parser.add_argument("timestamp", type=int, help="64b timestamp to use")
    args = parser.parse_args()

    encoder = Encoder(args.secrets_file.read())
    print(repr(encoder.encode(args.channel, args.frame.encode(), args.timestamp)))


if __name__ == "__main__":
    main()
