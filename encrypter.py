#!/usr/bin/env python3
"""File encrypter using AES-256-GCM with a scrypt-derived key."""
import argparse
import getpass
import os
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"AESGCM01"   # identifies our file format and version
SALT_LEN = 16
NONCE_LEN = 12        # standard 96-bit nonce for GCM


def derive_key(password: str, salt: bytes) -> bytes:
    """Stretch a password into a 256-bit key. Scrypt is deliberately slow
    and memory-hungry, which makes brute-forcing passwords expensive."""
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    return kdf.derive(password.encode())


def encrypt_file(path: str, out_path: str, password: str) -> None:
    with open(path, "rb") as f:
        plaintext = f.read()

    salt = os.urandom(SALT_LEN)    # fresh random salt per file
    nonce = os.urandom(NONCE_LEN)  # fresh random nonce per encryption
    key = derive_key(password, salt)

    header = MAGIC + salt + nonce
    # The header is authenticated too, so tampering with it is detected.
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, header)

    with open(out_path, "wb") as f:
        f.write(header + ciphertext)


def decrypt_file(path: str, out_path: str, password: str) -> None:
    with open(path, "rb") as f:
        blob = f.read()

    header_len = len(MAGIC) + SALT_LEN + NONCE_LEN
    if len(blob) < header_len + 16 or not blob.startswith(MAGIC):
        sys.exit("Error: not a valid encrypted file.")

    header = blob[:header_len]
    salt = blob[len(MAGIC):len(MAGIC) + SALT_LEN]
    nonce = blob[len(MAGIC) + SALT_LEN:header_len]
    ciphertext = blob[header_len:]

    key = derive_key(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, header)
    except InvalidTag:
        sys.exit("Error: wrong password, or the file has been tampered with.")

    with open(out_path, "wb") as f:
        f.write(plaintext)


def main():
    p = argparse.ArgumentParser(description="AES-256-GCM file encrypter")
    p.add_argument("mode", choices=["encrypt", "decrypt"])
    p.add_argument("file")
    p.add_argument("-o", "--out", help="output path")
    p.add_argument("--force", action="store_true", help="overwrite existing output")
    args = p.parse_args()

    if not os.path.isfile(args.file):
        sys.exit(f"Error: {args.file} not found.")

    if args.out:
        out = args.out
    elif args.mode == "encrypt":
        out = args.file + ".enc"
    else:
        out = args.file[:-4] if args.file.endswith(".enc") else args.file + ".dec"

    if os.path.exists(out) and not args.force:
        sys.exit(f"Error: {out} already exists (use --force to overwrite).")

    password = getpass.getpass("Password: ")
    if args.mode == "encrypt":
        if password != getpass.getpass("Confirm password: "):
            sys.exit("Error: passwords do not match.")
        encrypt_file(args.file, out, password)
    else:
        decrypt_file(args.file, out, password)

    print(f"{args.mode.capitalize()}ed -> {out}")


if __name__ == "__main__":
    main()

