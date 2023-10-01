import io
import random as rd
from typing import NamedTuple
import numpy as np
import sympy as sp


class InputData(NamedTuple):
    input_file: str
    output_file: str
    text: str
    keyword: str
    block_size: int


def chrl(num):
    return chr(ord('a') + num)


def clean_text(text):
    return text.replace('\n', ' ').strip()


ALPHABET = {chrl(i): i for i in range(26)}
ALPHABET[' '] = 26
ALPHABET[','] = 27
ALPHABET['.'] = 28

ALPHABET_INV = {i: chrl(i) for i in range(26)}
ALPHABET_INV[26] = ' '
ALPHABET_INV[27] = ','
ALPHABET_INV[28] = '.'


def make_key_matrix(keyword, n):
    fill = n * n - len(keyword)
    if fill > 0:
        keyword += ''.join([rd.choice(list(ALPHABET.keys())) for _ in range(fill)])
    if fill < 0:
        keyword = keyword[: n * n]
    return np.array([ALPHABET[l] for l in keyword]).reshape((n, n))


def blocks(text, n):
    rows, fill = divmod(len(text), n)
    if fill > 0:
        rows += 1
        text += ''.join([rd.choice(list(ALPHABET.keys())) for _ in range(n - fill)])
    return np.array([ALPHABET[l] for l in text]).reshape((rows, n))


def hill_encrypt(text, key_matrix):
    ciphertext = io.StringIO()
    n, _ = key_matrix.shape
    alen = len(ALPHABET)
    for b in blocks(text, n):
        enc_vec = np.matmul(key_matrix, b)
        enc_str = ''.join([ALPHABET_INV[i % alen] for i in enc_vec])
        ciphertext.write(enc_str)
    return ciphertext.getvalue()


def hill_decrypt(text, key_matrix):
    return hill_encrypt(text, sp.Matrix(key_matrix).inv_mod(len(ALPHABET)))


def read_input():
    infile = input('Enter the input filename: ')
    outfile = input('Enter the output filename: ')
    keyword = clean_text(input('Enter the keyword: '))
    block_size = int(input('Enter the block size: '))
    with open(infile, 'r') as f:
        text = clean_text(f.read())
        return InputData(infile, outfile, text, keyword, block_size)


def menu_encrypt(data):
    key_matrix = make_key_matrix(data.keyword, data.block_size)
    ciphertext = hill_encrypt(data.text, key_matrix)
    with open(data.output_file, 'w') as f:
        f.write(ciphertext)


def menu_decrypt(data):
    key_matrix = make_key_matrix(data.keyword, data.block_size)
    plaintext = hill_decrypt(data.text, key_matrix)
    with open(data.output_file, 'w') as f:
        f.write(plaintext)


def menu_print(data):
    print('Input:')
    with open(data.input_file, 'r') as f:
        print(f.read())
    print('Output:')
    with open(data.output_file, 'r') as f:
        print(f.read())


def main():
    data = read_input()

    while True:
        try:
            opt = int(
                input(
                    '1. Encrypt\n2. Decrypt\n3. Print results\n4. Reinput data\n5. Exit\n >>> '
                )
            )
        except Exception:
            print('Wrong option! Try again.')
            continue

        if opt == 1:
            menu_encrypt(data)
        elif opt == 2:
            menu_decrypt(data)
        elif opt == 3:
            menu_print(data)
        elif opt == 4:
            data = read_input()
        elif opt == 5:
            break
        else:
            print('Wrong option! Try again.')


if __name__ == '__main__':
    main()
