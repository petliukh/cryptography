#include "shift_cipher.hpp"
#include "crypto_utils.hpp"

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

namespace cr = petliukh::cryptography;
namespace fs = std::filesystem;

TEST(shift_cipher_test, sets_key_correctly)
{
    cr::Shift_cipher cipher;
    cipher.set_key(u"6");

    EXPECT_EQ(cipher.get_key(), 6);
}

TEST(shift_cipher_test, encrypts_decrypts_correctly_en)
{
    cr::Shift_cipher cipher;
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

TEST(shift_cipher_test, encrypts_decrypts_correctly_ukr)
{
    cr::Shift_cipher cipher;
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

TEST(shift_cipher_test, encrypts_decrypts_raw_bytes_correctly)
{
    auto opts
            = std::ios::in | std::ios::out | std::ios::binary | std::ios::trunc;

    std::string tmp_fname = "temp.tmp";
    std::fstream file(tmp_fname, opts);

    file << "Hello, world! Привіт, світ! Орео, орео +_)(*&^%$#@!~!@#$%^&*()_+"
            "Ми живемо в час змін, коли технології розвиваються зі швидкістю "
            "світла."
            "Інтернет, комп'ютери, смартфони, телевізори, ігрові консолі - все "
            "це стало"
            "частиною нашого повсякденного життя. Але чи завжди ми знаємо, як"
            "використовувати ці засоби правильно і безпечно?";

    file.seekg(0);

    std::string file_bytes(
            (std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>());

    fs::remove(tmp_fname);

    cr::Shift_cipher cipher;
    cipher.set_key(6);

    std::string encrypted_bytes = cipher.encrypt_raw_bytes(file_bytes);
    std::string decrypted_bytes = cipher.decrypt_raw_bytes(encrypted_bytes);

    ASSERT_FALSE(encrypted_bytes.empty());
    ASSERT_FALSE(decrypted_bytes.empty());

    std::string checksum1 = cr::sha256(file_bytes);
    std::string checksum2 = cr::sha256(decrypted_bytes);

    EXPECT_EQ(checksum1, checksum2);
}

TEST(shift_cipher_test, bruteforce_breaks_cipher_en)
{
    int key = 6;
    std::u16string message = u"Hello, world!";

    cr::Shift_cipher cipher;
    cipher.set_lang(u"EN");
    cipher.set_key(key);

    std::string checksum1 = cr::sha256(message);

    std::u16string encrypted = cipher.encrypt(message);
    auto messages = cipher.brute_force(encrypted);

    ASSERT_FALSE(messages.empty());

    auto is_decr = [&](const auto& pair) {
        std::string checksum2 = cr::sha256(pair.second);
        return checksum1 == checksum2 && pair.first == key;
    };

    auto decr_msg = std::find_if(messages.begin(), messages.end(), is_decr);

    EXPECT_NE(decr_msg, messages.end());
}
