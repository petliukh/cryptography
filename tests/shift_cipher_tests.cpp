#include "shift_cipher.hpp"

#include <gtest/gtest.h>

namespace cr = petliukh::cryptography;

TEST(shift_cipher_test, encrypts_decrypts_correctly_en) {
    cr::shift_cipher cipher;
    cipher.set_key(6);
    cipher.set_lang(u"EN");

    std::u16string message = u"Hello, world!";
    std::u16string encrypted = cipher.encrypt(message);
    std::u16string decrypted = cipher.decrypt(encrypted);

    ASSERT_FALSE(encrypted.empty());
    ASSERT_FALSE(decrypted.empty());

    std::string checksum1 = cr::sha256(message);
    std::string checksum2 = cr::sha256(decrypted);

    EXPECT_EQ(checksum1, checksum2);
}

TEST(shift_cipher_test, encrypts_decrypts_correctly_ukr) {
    cr::shift_cipher cipher;
    cipher.set_key(6);
    cipher.set_lang(u"UKR");

    std::u16string message = u"Привіт, світ!";
    std::u16string encrypted = cipher.encrypt(message);
    std::u16string decrypted = cipher.decrypt(encrypted);

    ASSERT_FALSE(encrypted.empty());
    ASSERT_FALSE(decrypted.empty());

    std::string checksum1 = cr::sha256(message);
    std::string checksum2 = cr::sha256(decrypted);

    EXPECT_EQ(checksum1, checksum2);
}

TEST(shift_cipher_test, encrypts_decrypts_raw_bytes_correctly) {
    auto opts
            = std::ios::in | std::ios::out | std::ios::binary | std::ios::trunc;

    std::string tmp_fname = "temp.tmp";
    std::fstream file(tmp_fname, opts);

    file << "Hello, world! Привіт, світ! +_)(*&^%$#@!~!@#$%^&*()_+";
    file.seekg(0);

    std::string file_bytes(
            (std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>());

    cr::shift_cipher cipher;
    cipher.set_key(6);

    std::string encrypted_bytes = cipher.encrypt_raw_bytes(file_bytes);
    std::string decrypted_bytes = cipher.decrypt_raw_bytes(encrypted_bytes);

    ASSERT_FALSE(encrypted_bytes.empty());
    ASSERT_FALSE(decrypted_bytes.empty());

    std::string checksum1 = cr::sha256(file_bytes);
    std::string checksum2 = cr::sha256(decrypted_bytes);

    EXPECT_EQ(checksum1, checksum2);

    remove(tmp_fname.c_str());
}
