#include "shift_cipher.hpp"

#include <gtest/gtest.h>

namespace cr = petliukh::cryptography;

TEST(shift_cipher_test, encrypts_decrypts_correctly_en) {
    cr::shift_cipher cipher;
    cipher.set_key(6);
    cipher.set_lang(u"EN");

    std::u16string message = u"Hello, world!";
    std::string checksum1 = cr::sha256(message);
    std::u16string encrypted = cipher.encrypt(message);
    std::u16string decrypted = cipher.decrypt(encrypted);
    std::string checksum2 = cr::sha256(decrypted);

    EXPECT_EQ(checksum1, checksum2);
}

TEST(shift_cipher_test, encrypts_decrypts_correctly_ukr) {
    cr::shift_cipher cipher;
    cipher.set_key(6);
    cipher.set_lang(u"UKR");

    std::u16string message = u"Привіт, світ!";
    std::string checksum1 = cr::sha256(message);
    std::u16string encrypted = cipher.encrypt(message);
    std::u16string decrypted = cipher.decrypt(encrypted);
    std::string checksum2 = cr::sha256(decrypted);

    EXPECT_EQ(checksum1, checksum2);
}
