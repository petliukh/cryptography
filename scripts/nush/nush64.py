import argparse
import secrets


def bitwise_and(a, b):
    return a & b


def bitwise_or(a, b):
    return a ^ b


SHIFT_TABLE = [
    [4, 7, 11, 8],
    [7, 14, 5, 4],
    [8, 2, 9, 4],
    [13, 1, 14, 6],
    [7, 12, 5, 1],
    [2, 4, 12, 3],
    [9, 2, 11, 13],
    [12, 3, 6, 11],
    [7, 15, 4, 14],
]

LOGICAL_OPS_TABLE = [
    [bitwise_and, bitwise_or, bitwise_and, bitwise_or],
    [bitwise_or, bitwise_or, bitwise_or, bitwise_or],
    [bitwise_and, bitwise_or, bitwise_or, bitwise_and],
    [bitwise_or, bitwise_and, bitwise_or, bitwise_or],
    [bitwise_or, bitwise_or, bitwise_and, bitwise_and],
    [bitwise_and, bitwise_and, bitwise_and, bitwise_or],
    [bitwise_and, bitwise_or, bitwise_or, bitwise_or],
    [bitwise_and, bitwise_or, bitwise_and, bitwise_and],
    [bitwise_or, bitwise_or, bitwise_and, bitwise_or],
]

MODIFYING_CONSTANTS_TABLE = [
    [0xAC25, 0x8A93, 0x243D, 0x262E],
    [0xF887, 0xC4F2, 0x8E36, 0x9FA1],
    [0x7DC0, 0x6A29, 0x6D84, 0x34BD],
    [0xA267, 0xCC15, 0x04FE, 0xB94A],
    [0xDF24, 0x40EF, 0x96DA, 0x905F],
    [0xD631, 0xAA62, 0x4D15, 0x70CB],
    [0x7533, 0x45FC, 0x5337, 0xD25E],
    [0xA926, 0x1C7B, 0x5F12, 0x4ECC],
    [0x3C86, 0x28DB, 0xFC01, 0x7CB1],
]


def create_parsers():
    parser = argparse.ArgumentParser(
        description="NUSH cipher algorithm argument parser"
    )
    subpars = parser.add_subparsers(dest="command")
    keygenp = subpars.add_parser("keygen")
    encryptp = subpars.add_parser("encrypt")
    decryptp = subpars.add_parser("decrypt")

    keygenp.add_argument("-b", "--bits", type=int, default=256)
    keygenp.add_argument("-o", "--output", type=str, required=True)

    encryptp.add_argument("input")
    encryptp.add_argument("-o", "--output", type=str, required=True)
    encryptp.add_argument("-k", "--key", type=str, required=True)

    decryptp.add_argument("input")
    decryptp.add_argument("-o", "--output", type=str, required=True)
    decryptp.add_argument("-k", "--key", type=str, required=True)

    return parser.parse_args()


def read_bytes(filename):
    with open(filename, "rb") as bfile:
        return bfile.read()


def write_bytes(wbytes, filename):
    with open(filename, "wb") as bfile:
        bfile.write(wbytes)


def blocks(bytearr, size):
    return [bytearr[i : i + size] for i in range(0, len(bytearr), size)]


def blocks64(bytearr):
    return blocks(bytearr, 8)


def blocks16(bytearr):
    return blocks(bytearr, 2)


def generate_key(bits):
    bytes_num = bits // 8
    return secrets.token_bytes(bytes_num)


def int_to_bytes(i):
    return i.to_bytes(2, "big")


def int_from_bytes(block):
    return int.from_bytes(block, byteorder="big", signed=False)


def get_iter_key(r, i, key256):
    c = MODIFYING_CONSTANTS_TABLE[r][i]
    it = r * 4 + i
    return (int_from_bytes(key256[it % 16]) + c) % 2**16


def xor_transform(block, key256, frag_indices):
    block = blocks16(block)
    key256 = blocks16(key256)
    key_frags = [key256[i] for i in frag_indices]
    tblock = [
        a ^ b
        for a, b in zip(map(int_from_bytes, block), map(int_from_bytes, key_frags))
    ]
    tblock = list(map(int_to_bytes, tblock))
    res = []
    for sb in tblock:
        res.extend(sb)
    return res


def round_enc(r, block64, key256):
    (y1, y2, y3, y4) = list(map(int_from_bytes, blocks16(block64)))
    key_b16 = blocks16(key256)

    for i in range(4):
        lop = LOGICAL_OPS_TABLE[r][i]
        s = SHIFT_TABLE[r][i]
        kri = get_iter_key(r, i, key_b16)
        y3 = ((y2 + (y3 ^ kri)) % 2**16) >> s
        y1 = (y1 + lop(y3, y4)) % 2**16

    qrt = list(map(int_to_bytes, (y1, y2, y3, y4)))
    res = []
    for q in qrt:
        res.extend(q)
    return res


def round_dec(r, block64, key256):
    (y1, y2, y3, y4) = list(map(int_from_bytes, blocks16(block64)))
    key_b16 = blocks16(key256)

    for i in range(3, -1, -1):
        lop = LOGICAL_OPS_TABLE[r][i]
        s = SHIFT_TABLE[r][i]
        kri = get_iter_key(r, i, key_b16)
        y1 = (y1 - lop(y3, y4)) % 2**16
        y3 = ((y3 >> (16 - s)) ^ kri - y2) % 2**16

    qrt = list(map(int_to_bytes, (y1, y2, y3, y4)))
    res = []
    for q in qrt:
        res.extend(q)
    return res


def nush64_encrypt(bytestr, key256):
    if len(key256) != 32:
        raise ValueError("Wrong key length")

    bytearr = bytearray(bytestr)
    ciphertext = []

    for block in blocks(bytearr, 8):
        block = xor_transform(block, key256, [12, 13, 14, 15])
        for i in range(9):
            block = round_enc(i, block, key256)
        block = xor_transform(block, key256, [13, 12, 15, 14])
        ciphertext.extend(block)

    return bytes(ciphertext)


def nush64_decrypt(bytestr, key256):
    if len(key256) != 32:
        raise ValueError("Wrong key length")

    bytearr = bytearray(bytestr)
    ciphertext = []

    for block in blocks(bytearr, 8):
        block = xor_transform(block, key256, [13, 12, 15, 14])
        for i in range(8, -1, -1):
            block = round_dec(i, block, key256)
        block = xor_transform(block, key256, [12, 13, 14, 15])
        ciphertext.extend(block)

    return bytes(ciphertext)


def complete_plaintext_len(plaintext):
    rest = len(plaintext) % 8
    if rest:
        plaintext += secrets.token_bytes(8 - rest)
    return plaintext


def menu_keygen(parser):
    key = generate_key(parser.bits)
    write_bytes(key, parser.output)


def menu_encrypt(parser):
    plaintext = complete_plaintext_len(read_bytes(parser.input))
    key = read_bytes(parser.key)
    ciphertext = nush64_encrypt(plaintext, key)
    write_bytes(ciphertext, parser.output)


def menu_decrypt(parser):
    ciphertext = read_bytes(parser.input)
    key = read_bytes(parser.key)
    plaintext = nush64_decrypt(ciphertext, key)
    write_bytes(plaintext, parser.output)


def main():
    parser = create_parsers()

    if parser.command == "keygen":
        menu_keygen(parser)
    elif parser.command == "encrypt":
        menu_encrypt(parser)
    elif parser.command == "decrypt":
        menu_decrypt(parser)


if __name__ == "__main__":
    main()
