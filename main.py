import hashlib
import base64

# Implementation from the Tor v3 specification.
# https://github.com/torproject/torspec/blob/main/rend-spec-v3.txt#L2259C1-L2272C81

with open('hs_ed25519_public_key', 'rb') as key_file:
    key_file.seek(32)
    key_bytes = key_file.read()

if len(key_bytes) != 32:
    print(len(key_bytes))
    raise ValueError("Invalid Ed25519 public key length")

def main():
    VERSION = b'\x03'
    CHECKSUM_CONSTANT = b".onion checksum"

    data = CHECKSUM_CONSTANT + key_bytes + VERSION
    checksum = hashlib.sha3_256(data).digest()[:2]

    onion_data = key_bytes + checksum + VERSION
    onion_address = base64.b32encode(onion_data).decode('utf-8')+".onion"

    print(f"{onion_address.lower()}")

if __name__ == '__main__':
    main()