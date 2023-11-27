import numpy as np
import sympy as sp
import random as rd
import typing as tp
import argparse
import io


# =============================================================================
# Heplers
# =============================================================================


class PublicKey(tp.NamedTuple):
    q: int
    g: int
    h: int

    def __str__(self):
        return f"{self.q} {self.g} {self.h}"


def modpow(a, b, m):
    x = 1
    y = a

    while b > 0:
        if b % 2 != 0:
            x = (x * y) % m
        y = (y * y) % m
        b = int(b / 2)

    return x % m


# =============================================================================
# Key Generation
# =============================================================================


def cyclicggen(fro, to):
    a = rd.randint(fro, to)
    while np.gcd(a, to) != 1:
        a = sp.nextprime(a)
    return a


def keygen(order_from, order_to):
    q = rd.randint(10**order_from, 10**order_to)
    g = rd.randint(2, q)
    a = cyclicggen(10**order_from, q)
    h = modpow(g, a, q)
    return PublicKey(q, g, h), a


def pairgen(pubk):
    q, g = pubk.q, pubk.g
    k = cyclicggen(q // 2, q)
    p = modpow(g, k, q)
    return k, p


# =============================================================================
# Encrypt / Decrypy
# =============================================================================


def elgamal_encrypt(plaintext, pubk, k):
    q, g, h = pubk
    s = modpow(h, k, q)
    ciphertext = io.StringIO()

    for c in plaintext:
        enc = ord(c) * s
        ciphertext.write(f"{enc} ")
    return ciphertext.getvalue()


def elgamal_decrypt(ciphertext, privk, pubk, p):
    plaintext = io.StringIO()
    s = modpow(p, privk, pubk.q)

    for c in ciphertext.split():
        dec = chr(int(c) // s)
        plaintext.write(dec)
    return plaintext.getvalue()


# =============================================================================
# File Read / Write
# =============================================================================


def write_file(filename, content):
    with open(filename, "w") as fout:
        fout.write(content)


def read_file(filename):
    with open(filename, "r") as fin:
        return fin.read()


def read_pubk(filename):
    nums = read_file(filename).split()
    q, g, h = list(map(int, nums))
    return PublicKey(q, g, h)


def read_number(filename):
    return int(read_file(filename))


def write_obj(filename, obj):
    write_file(filename, str(obj))


# =============================================================================
# Menu Functions
# =============================================================================


def menu_keygen(parser):
    public_key, private_key = keygen(parser.order_to // 2, parser.order_to)
    write_obj(f"{parser.output}.pub", public_key)
    write_obj(f"{parser.output}.priv", private_key)


def menu_pairgen(parser):
    pubk = read_pubk(parser.pubk)
    k, p = pairgen(pubk)
    write_obj(f"{parser.output}.privp", k)
    write_obj(f"{parser.output}.pubp", p)


def menu_encrypt(parser):
    plaintext = read_file(parser.input)
    k = read_number(parser.pairk)
    pubk = read_pubk(parser.pubk)
    ciphertext = elgamal_encrypt(plaintext, pubk, k)
    write_file(parser.output, ciphertext)


def menu_decrypt(parser):
    ciphertext = read_file(parser.input)
    privk = read_number(parser.privk)
    pubk = read_pubk(parser.pubk)
    p = read_number(parser.pairk)
    plaintext = elgamal_decrypt(ciphertext, privk, pubk, p)
    write_file(parser.output, plaintext)


def create_parsers():
    parser = argparse.ArgumentParser(description="Elgamal Algorithm Implementation")
    subpars = parser.add_subparsers(dest="command")

    keygenp = subpars.add_parser("keygen")
    pairgenp = subpars.add_parser("pairgen")
    encryptp = subpars.add_parser("encrypt")
    decryptp = subpars.add_parser("decrypt")

    keygenp.add_argument("-t", "--order-to", type=int, default=60)
    keygenp.add_argument("-o", "--output", type=str, required=True)

    pairgenp.add_argument("pubk", type=str)
    pairgenp.add_argument("-o", "--output", type=str, required=True)

    encryptp.add_argument("input", type=str)
    encryptp.add_argument("-k", "--pubk", type=str, required=True)
    encryptp.add_argument("-p", "--pairk", type=str, required=True)
    encryptp.add_argument("-o", "--output", type=str, required=True)

    decryptp.add_argument("input", type=str)
    decryptp.add_argument("-k", "--privk", type=str, required=True)
    decryptp.add_argument("-u", "--pubk", type=str, required=True)
    decryptp.add_argument("-p", "--pairk", type=str, required=True)
    decryptp.add_argument("-o", "--output", type=str, required=True)

    return parser.parse_args()


def main():
    parser = create_parsers()

    if parser.command == "keygen":
        menu_keygen(parser)
    elif parser.command == "pairgen":
        menu_pairgen(parser)
    elif parser.command == "encrypt":
        menu_encrypt(parser)
    elif parser.command == "decrypt":
        menu_decrypt(parser)


if __name__ == "__main__":
    main()
