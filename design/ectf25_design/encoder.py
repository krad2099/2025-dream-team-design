import argparse
import struct
import json
from OpenSSL import crypto

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

        # Define AES key for encryption (using the same key as in gen_secrets)
        self.key = b"super_secure_key_32bytes_for_aes"  # Use the same key

    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        """The frame encoder function

        This will be called for every frame that needs to be encoded before being
        transmitted by the satellite to all listening TVs

        :param channel: 16b unsigned channel number. Channel 0 is the emergency
            broadcast that must be decodable by all channels.
        :param frame: Frame to encode. Max frame size is 64 bytes.
        :param timestamp: 64b timestamp to use for encoding. **NOTE**: This value may
            have no relation to the current timestamp, so you should not compare it
            against the current time. The timestamp is guaranteed to strictly
            monotonically increase (always go up) with subsequent calls to encode

        :returns: The encoded frame, which will be sent to the Decoder
        """
        # Encrypt the frame using AES from OpenSSL (pyOpenSSL)
        cipher = crypto.Cipher('aes_256_cbc', self.key, iv=b'0123456789abcdef', mode=crypto.Cipher.MODE_CBC)
        encrypted_frame = cipher.encrypt(frame)

        # Return the encoded frame with the channel and timestamp
        return struct.pack("<IQ", channel, timestamp) + encrypted_frame


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
