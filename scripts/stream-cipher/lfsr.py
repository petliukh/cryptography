start_state = 1 << 7 | 1
print("Start state: ", bin(start_state))
lfsr = start_state
period = 0

key = []

while True:
    #taps: 8 6 2 1; feedback polynomial: x^8 + x^6 + x^2 + 1
    bit = (lfsr ^ (lfsr >> 2) ^ (lfsr >> 6)) & 1
    lfsr = (lfsr >> 1) | (bit << 7)
    period += 1
    key.insert(0, bit)
    if (lfsr == start_state):
        print("Period: ", period)
        print("Key: ", key)
        break


def xor_text(plaintext_z2, key):
    return [a ^ b for a, b in zip(plaintext_z2, key)]


plaintext_z2 = [1, 0, 0, 1, 0, 1, 1, 0]

print("Plaintext: ", plaintext_z2)
encrypted = xor_text(plaintext_z2, key)

print("Encrypted: ", encrypted)
print("Decrypted: ", xor_text(encrypted, key))
