from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from os import urandom
import argparse
import base64
import gnupg
import json
import sys
import re

encoding = 'utf-8'
def chacha_encrypt(data, key=None, nonce=None, aad=None):
    if not key:
        key = ChaCha20Poly1305.generate_key()

    if not nonce:
        nonce = urandom(12)

    cipher = ChaCha20Poly1305(key)
    ct = cipher.encrypt(nonce, data, aad)
    return ct, key, nonce, aad


def chacha_decrypt(data, key, nonce, aad=None):
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, data, aad)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Encrypt everything!!")
    parser.add_argument('-l', action='store_true', required=False, help='List GPG keys.')
    parser.add_argument('-e', action='store_true', required=False, help='Do encryption from stdin.')
    parser.add_argument('-d', action='store_true', required=False, help='Do decryption from stdin.')
    parser.add_argument('-r', action='store', required=False, help='Recipient for the message.')
    parser.add_argument('-p', action='store', required=False, help='Passphrase for RSA decryption.')
    args = parser.parse_args()

    if args.l:
        gpg = gnupg.GPG()
        public_keys = gpg.list_keys()
        for key in public_keys:
            print(" ".join(key['uids']) + " " + key['keyid'])
        exit(1)

    if args.e and args.d:
        print("Choode -e or -d but not both!", file=sys.stderr)
        exit(-1)

    if args.e:
        recipient = args.r

        stdinput = sys.stdin.readlines()
        stdinput = "".join(stdinput)
        stdinput = stdinput.rstrip()
        ct, key, nonce, aad = chacha_encrypt(bytes(stdinput, encoding))

        if not aad:
            aad = b''

        header_data = {
            "key": str(base64.b64encode(key), encoding),
            "nonce": str(base64.b64encode(nonce), encoding),
            "aad": str(base64.b64encode(aad), encoding),
        }
        gpg = gnupg.GPG()
        header_json = json.dumps(header_data)
        encrypted_data = gpg.encrypt(header_json, recipient)

        print(str(encrypted_data))
        print(str(base64.b64encode(ct), encoding))
        exit(1)

    if args.d:
        gpg = gnupg.GPG()

        stdinput = sys.stdin.readlines()
        stdinput = "".join(stdinput)
        stdinput = stdinput.rstrip()

        gpgre = re.compile("-----BEGIN PGP MESSAGE-----([\S\s]*?)-----END PGP MESSAGE-----")
        match = gpgre.match(stdinput)
        if not match:
            print("No PGP message attached. Exiting.", file=sys.stderr)
            exit(-1)

        stdinput = gpgre.sub("", stdinput)

        if args.p:
            header_json = str(gpg.decrypt(match[0], passphrase=args.p))
        else:
            header_json = str(gpg.decrypt(match[0]))

        header_json = json.loads(header_json)
        key = base64.b64decode(header_json['key'])
        nonce = base64.b64decode(header_json['nonce'])
        aad = base64.b64decode(header_json['aad'])

        stdinput = base64.b64decode(stdinput)
        ret = chacha_decrypt(stdinput, key, nonce, None)

        print(ret.decode(encoding))
        exit(1)
