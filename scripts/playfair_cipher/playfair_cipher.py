import io
from typing import NamedTuple


INSERT_LETTER = "X"
OMIT_LETTER = "J"
ALPHABET = {chr(ord("A") + i) for i in range(26)} - {OMIT_LETTER}


class InputData(NamedTuple):
    text: str
    keyword: str
    input_file: str
    output_file: str


def clean_text(text):
    return (
        text.replace(" ", "")
        .replace(",", "")
        .replace(".", "")
        .replace("\n", "")
        .upper()
        .strip()
    )


def make_key_table(letter_set):
    rest = sorted(ALPHABET - letter_set)
    table = [*letter_set, *rest]
    return table


def digrams(plaintext):
    size = len(plaintext)
    plaintext = plaintext.replace(OMIT_LETTER, INSERT_LETTER)
    for i in range(0, size, 2):
        if i == size - 1 or plaintext[i] == plaintext[i + 1]:
            yield (plaintext[i], INSERT_LETTER)
        else:
            yield (plaintext[i], plaintext[i + 1])


def _playfair_encrypt(plaintext, key_table):
    ciphertext = io.StringIO()

    for l1, l2 in digrams(plaintext):
        l1_idx = key_table.index(l1)
        l1_row, l1_col = divmod(l1_idx, 5)

        l2_idx = key_table.index(l2)
        l2_row, l2_col = divmod(l2_idx, 5)

        if l1_row == l2_row:
            s1_row = s2_row = l1_row
            s1_col = (l1_col + 1) % 5
            s2_col = (l2_col + 1) % 5
        elif l1_col == l2_col:
            s1_col = s2_col = l1_col
            s1_row = (l1_row + 1) % 5
            s2_row = (l2_row + 1) % 5
        else:
            s1_row = l1_row
            s1_col = l2_col
            s2_row = l2_row
            s2_col = l1_col

        s1_idx = s1_row * 5 + s1_col
        s2_idx = s2_row * 5 + s2_col
        ciphertext.write(key_table[s1_idx])
        ciphertext.write(key_table[s2_idx])

    return ciphertext.getvalue()


def _playfair_decrypt(ciphertext, key_table):
    plaintext = io.StringIO()

    for l1, l2 in digrams(ciphertext):
        l1_idx = key_table.index(l1)
        l1_row, l1_col = divmod(l1_idx, 5)

        l2_idx = key_table.index(l2)
        l2_row, l2_col = divmod(l2_idx, 5)

        if l1_row == l2_row:
            s1_row = s2_row = l1_row
            s1_col = (l1_col - 1) % 5
            s2_col = (l2_col - 1) % 5
        elif l1_col == l2_col:
            s1_col = s2_col = l1_col
            s1_row = (l1_row - 1) % 5
            s2_row = (l2_row - 1) % 5
        else:
            s1_row = l1_row
            s1_col = l2_col
            s2_row = l2_row
            s2_col = l1_col

        s1_idx = s1_row * 5 + s1_col
        s2_idx = s2_row * 5 + s2_col
        plaintext.write(key_table[s1_idx])
        plaintext.write(key_table[s2_idx])

    return plaintext.getvalue()


def playfair_encrypt(plaintext, keyword):
    key_table = make_key_table(set(clean_text(keyword)))
    return _playfair_encrypt(clean_text(plaintext), key_table)


def playfair_decrypt(ciphertext, keyword):
    key_table = make_key_table(set(clean_text(keyword)))
    return _playfair_decrypt(clean_text(ciphertext), key_table)


def digrams_str(text):
    return " ".join([d[0] + d[1] for d in digrams(clean_text(text))])


def read_input():
    input_file = input("Enter the input filename: ")
    output_file = input("Enter the output filename: ")
    keyword = input("Enter the keyword: ")
    with open(input_file, "r") as f:
        plaintext = f.read()
        return InputData(plaintext, keyword, input_file, output_file)


def write_output(output_file, ciphertext):
    with open(output_file, "w") as f:
        f.write(ciphertext)


def print_files_data(input_data):
    with open(input_data.input_file, "r") as f:
        print("Input:\n", digrams_str(f.read()))
    with open(input_data.output_file, "r") as f:
        print("Output:\n", digrams_str(f.read()))


def main():
    input_data = read_input()

    while True:
        try:
            opt = int(
                input(
                    "Enter the option:\n1. Encrypt\n2. Decrypt\n3. Print files\n4. Reinput data\n5. Exit\n >>> "
                )
            )
        except Exception:
            print("Wrong option!\nTry again >>> ")
            continue

        if opt == 1:
            ciphertext = playfair_encrypt(input_data.text, input_data.keyword)
            write_output(input_data.output_file, ciphertext)
        elif opt == 2:
            plaintext = playfair_decrypt(input_data.text, input_data.keyword)
            write_output(input_data.output_file, plaintext)
        elif opt == 3:
            print_files_data(input_data)
        elif opt == 4:
            input_data = read_input()
        elif opt == 5:
            break
        else:
            print("Wrong option!\nTry again >>> ")
        print("=-" * 20)


if __name__ == "__main__":
    main()
