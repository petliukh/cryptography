#include "shift_cipher.hpp"

#include <fstream>
#include <gtest/gtest.h>
#include <vector>

using petliukh::cryptography::message;
using petliukh::cryptography::shift_cipher;
using std::fstream, std::ofstream, std::ifstream, std::ios;
using std::u16string, std::string;
using std::vector;

TEST(ShiftCipherTest, EncryptsAndDecryptsCorrectly) {
    shift_cipher cipher_en(u"EN");
    int key = 3;

    u16string plaintext_en = u"To be, or not to be, that is the question";
    u16string ciphertext_en = cipher_en.encrypt_text(plaintext_en, key);
    u16string decrypted_en = cipher_en.decrypt_text(ciphertext_en, key);
    EXPECT_EQ(decrypted_en, plaintext_en);

    shift_cipher cipher_uk(u"UKR");

    u16string plaintext_uk = u"І знову сутінки. Холод віддається вітром";
    u16string ciphertext_uk = cipher_uk.encrypt_text(plaintext_uk, key);
    u16string decrypted_uk = cipher_uk.decrypt_text(ciphertext_uk, key);
    EXPECT_EQ(decrypted_uk, plaintext_uk);
}

TEST(ShiftCipherTest, EncryptsAndDecryptsCorrectlyWithFile) {
    shift_cipher cipher_en;
    int key = 3;

    string initial_fname = "initial.bytes";
    string encrypted_fname = "encrypted.bytes";
    string decrypted_fname = "decrypted.bytes";
    string bytes = "ByTeS_To_EnCrYpT";

    ofstream file(initial_fname, ios::binary);
    file << bytes;
    file.close();

    cipher_en.encrypt_file(initial_fname, key, encrypted_fname);
    cipher_en.decrypt_file(encrypted_fname, key, decrypted_fname);

    // Open initial and decrypted files and compare their bytes
    ifstream ifs_initial(initial_fname, ios::binary);
    ifstream ifs_decrypted(decrypted_fname, ios::binary);

    char c_initial, c_decrypted;

    while (ifs_initial.get(c_initial) && ifs_decrypted.get(c_decrypted)) {
        EXPECT_EQ(c_initial, c_decrypted);
    }

    // remove temp files
    remove(initial_fname.c_str());
    remove(encrypted_fname.c_str());
    remove(decrypted_fname.c_str());
}

TEST(ShiftCipherTest, EncryptsAndDecryptsCorrectlyWithFileOverwrite) {
    shift_cipher cipher_en;
    int key = 3;

    string initial_fname = "initial_file.bytes";
    string bytes = "ByTeS_To_EnCrYpT";
    ofstream ofs_initial(initial_fname, ios::binary);
    ofs_initial << bytes;
    ofs_initial.close();

    cipher_en.encrypt_file(initial_fname, key);
    cipher_en.decrypt_file(initial_fname, key);

    ifstream ifs_initial(initial_fname, ios::binary);

    char c_decrypted;

    int8_t i = 0;
    while (ifs_initial.get(c_decrypted)) {
        EXPECT_EQ(c_decrypted, bytes[i]);
        i++;
    }

    ifs_initial.close();

    // remove temp files
    remove(initial_fname.c_str());
}

TEST(ShiftCipherTest, BruteForceWorksCorrectly) {
    shift_cipher cipher_en(u"EN");
    int key = 3;

    u16string plaintext_en = u"To be, or not to be, that is the question";
    u16string ciphertext_en = cipher_en.encrypt_text(plaintext_en, key);

    vector<message> messages = cipher_en.brute_force(ciphertext_en);

    for (auto& message : messages) {
        if (message.key == key) {
            EXPECT_EQ(message.text, plaintext_en);
        } else {
            EXPECT_NE(message.text, plaintext_en);
        }
    }
}
