import bbc


def stream_xor(plaintext_bytes, seed, m):
    ciphertext_bytes = []
    for byte in plaintext_bytes:
        rand_bits, seed = bbc.generate_bit_stream(seed, m, 8)
        ciphertext_bytes.append(byte ^ rand_bits)
    return bytes(ciphertext_bytes)


p, q = bbc.generate_pq(10)
seed = bbc.generate_seed(10)
m = p * q


print("M: ", m)
print("Seed: ", seed)

plaintext = "Hello, World!".encode("utf-8")
ciphertext = stream_xor(plaintext, seed, m)
deciphered = stream_xor(ciphertext, seed, m)

print("Plaintext: ", plaintext)
print("Ciphertext: ", ciphertext)
print("Deciphered: ", deciphered)
