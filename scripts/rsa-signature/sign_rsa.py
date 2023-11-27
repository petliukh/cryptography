import io
from typing import NamedTuple
import numpy as np
import sympy as sp
import random as rd
import hashlib


# =============================================================================
# RSA Algorithm
# =============================================================================


class PublicKey(NamedTuple):
    e: int
    N: int


class PrivateKey(NamedTuple):
    d: int
    N: int


def generate_large_primes(order):
    p = rd.randint(10 ** (order // 2), 10**order)
    q = rd.randint(10 ** (order // 2), 10**order)
    return sp.nextprime(p), sp.nextprime(q)


def generate_rsa_key(order):
    p, q = generate_large_primes(order)
    N = p * q
    phi = (p - 1) * (q - 1)
    e = rd.randint(order // 4, order // 2)

    while not (np.gcd(e, N) == 1 and np.gcd(e, phi) == 1) and e < phi:
        e = sp.nextprime(e)
    d = sp.mod_inverse(e, phi)

    return PublicKey(e, N), PrivateKey(d, N)


def rsa_encrypt(plaintext, pubk):
    ciphertext = io.StringIO()
    e, N = pubk

    for c in plaintext:
        enc = pow(ord(c), e, N)
        ciphertext.write(f"{enc} ")
    return ciphertext.getvalue()


def rsa_decrypt(ciphertext, privk):
    plaintext = io.StringIO()
    d, N = privk

    for i in map(int, ciphertext.split()):
        dec = chr(pow(i, d, N))
        plaintext.write(dec)
    return plaintext.getvalue()


# =============================================================================
                            # Digital Signature
# =============================================================================


def rsa_sign(message, privk):
    msg_hash = hashlib.sha256(message.encode()).hexdigest() 
    return rsa_encrypt(msg_hash, privk)


def verify(message, signature, pubk):
    msg_hash = hashlib.sha256(message.encode()).hexdigest() 
    orig_hash = rsa_decrypt(signature, pubk)
    return msg_hash == orig_hash


pubk, privk = generate_rsa_key(60)
plaintext = "Lorem ipsum dolor sit amet, consectetur adipiscing elit"
ciphertext = rsa_encrypt(plaintext, pubk)
deciphered = rsa_decrypt(ciphertext, privk)

signature = rsa_sign(plaintext, privk)
verified = verify(deciphered, signature, pubk)


print(pubk, "\n")
print(privk, "\n")
print(f"Plaintext:\n{plaintext}\n")
print(f"Ciphertext:\n{ciphertext[:256]}...\n")
print(f"Deciphered:\n{deciphered}\n")
print(f"Signature: {signature[:256]}...\n")
print(f"Verified: {verified}")
