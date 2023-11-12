import random as rd
import sympy as sp
import io


def check_conditions(prime):
    return (prime % 4) == 3 and sp.isprime(2 * prime + 1)


def generate_pq(start_digits):
    p = sp.randprime(10**start_digits, 2 * 10**start_digits)
    q = sp.randprime(10**start_digits, 2 * 10**start_digits)

    while not check_conditions(p):
        p = sp.nextprime(p)
    while not check_conditions(q):
        q = sp.nextprime(q)
    return p, q


def least_significant_bit(number):
    return number & 1


def generate_seed(start_digits):
    return rd.randint(10**start_digits, 2 * 10**start_digits)


def generate_bit_stream(seed, m, n_bits):
    x_n = seed
    bits = io.StringIO()

    for _ in range(n_bits):
        x_n = (x_n * x_n) % m
        bits.write(str(least_significant_bit(x_n)))
    return int(bits.getvalue(), 2), x_n
