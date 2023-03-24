#include "trithemius_cipher.hpp"

#include <gtest/gtest.h>

namespace cr = petliukh::cryptography;
using tkey = cr::Trithemius_cipher::key;
using tkey_type = cr::Trithemius_cipher::key_type;

TEST(tritemius_test, sets_key_correctly)
{
    cr::Trithemius_cipher cipher;
    cipher.set_lang(u"EN");
    cipher.set_key(u"1,2");
    tkey key = cipher.get_key();
    ASSERT_EQ(key.type, tkey_type::v2);
    ASSERT_EQ(key.key_v2.x(), 1);
    ASSERT_EQ(key.key_v2.y(), 2);

    cipher.set_key(u"1,2,3");
    key = cipher.get_key();
    ASSERT_EQ(key.type, tkey_type::v3);
    ASSERT_EQ(key.key_v3.x(), 1);
    ASSERT_EQ(key.key_v3.y(), 2);
    ASSERT_EQ(key.key_v3.z(), 3);

    cipher.set_key(u"keyword");
    key = cipher.get_key();
    ASSERT_EQ(key.type, tkey_type::word);
    ASSERT_EQ(key.keyword, u"keyword");

    ASSERT_THROW(cipher.set_key(u"1,2,3,4"), std::invalid_argument);
    ASSERT_THROW(cipher.set_key(u"1,2,3,4,5"), std::invalid_argument);
    ASSERT_THROW(cipher.set_key(u"гасло"), std::invalid_argument);
}

TEST(tritemius_test, encrypts_decrypts_v2_correctly)
{
    cr::Trithemius_cipher cipher;
    cipher.set_lang(u"EN");
    cipher.set_key(u"1,2");
    std::u16string message = u"Hello, world!";
    std::u16string encrypted = cipher.encrypt(message);
    std::u16string decrypted = cipher.decrypt(encrypted);
    std::string checksum1 = cr::sha256(message);
    std::string checksum2 = cr::sha256(decrypted);
    ASSERT_EQ(checksum1, checksum2);

    cipher.set_lang(u"UKR");
    cipher.set_key(u"1,2");
    message = u"Привіт, світ!";
    encrypted = cipher.encrypt(message);
    decrypted = cipher.decrypt(encrypted);
    checksum1 = cr::sha256(message);
    checksum2 = cr::sha256(decrypted);
    ASSERT_EQ(checksum1, checksum2);
}

TEST(tritemius_test, encrypts_decrypts_v3_correctly)
{
    cr::Trithemius_cipher cipher;
    cipher.set_lang(u"EN");
    cipher.set_key(u"1,2,3");
    std::u16string message = u"Hello, world!";
    std::u16string encrypted = cipher.encrypt(message);
    std::u16string decrypted = cipher.decrypt(encrypted);
    std::string checksum1 = cr::sha256(message);
    std::string checksum2 = cr::sha256(decrypted);
    ASSERT_EQ(checksum1, checksum2);

    cipher.set_lang(u"UKR");
    cipher.set_key(u"1,2,3");
    message = u"Привіт, світ!";
    encrypted = cipher.encrypt(message);
    decrypted = cipher.decrypt(encrypted);
    checksum1 = cr::sha256(message);
    checksum2 = cr::sha256(decrypted);
    ASSERT_EQ(checksum1, checksum2);
}

TEST(tritemius_test, encrypts_decrypts_kw_correctly)
{
    cr::Trithemius_cipher cipher;
    cipher.set_lang(u"EN");
    cipher.set_key(u"keyword");
    std::u16string message = u"Hello, world!";
    std::u16string encrypted = cipher.encrypt(message);
    std::u16string decrypted = cipher.decrypt(encrypted);
    std::string checksum1 = cr::sha256(message);
    std::string checksum2 = cr::sha256(decrypted);
    ASSERT_EQ(checksum1, checksum2);

    cipher.set_lang(u"UKR");
    cipher.set_key(u"гасло");
    message = u"Привіт, світ!";
    encrypted = cipher.encrypt(message);
    decrypted = cipher.decrypt(encrypted);
    checksum1 = cr::sha256(message);
    checksum2 = cr::sha256(decrypted);
    ASSERT_EQ(checksum1, checksum2);
}

TEST(tritemius_test, encrypts_decrypts_raw_bytes_v2_correctly)
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

    cr::Trithemius_cipher cipher;
    cipher.set_key(u"1,2");
    std::string encrypted_bytes = cipher.encrypt_raw_bytes(file_bytes);
    std::string decrypted_bytes = cipher.decrypt_raw_bytes(encrypted_bytes);
    std::string checksum1 = cr::sha256(file_bytes);
    std::string checksum2 = cr::sha256(decrypted_bytes);
    ASSERT_EQ(checksum1, checksum2);
}

TEST(tritemius_test, encrypts_decrypts_raw_bytes_v3_correctly)
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

    cr::Trithemius_cipher cipher;
    cipher.set_key(u"1,2,3");
    std::string encrypted_bytes = cipher.encrypt_raw_bytes(file_bytes);
    std::string decrypted_bytes = cipher.decrypt_raw_bytes(encrypted_bytes);
    std::string checksum1 = cr::sha256(file_bytes);
    std::string checksum2 = cr::sha256(decrypted_bytes);
    ASSERT_EQ(checksum1, checksum2);
}

TEST(tritemius_test, encrypts_decrypts_raw_bytes_kw_correctly)
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

    cr::Trithemius_cipher cipher;
    cipher.set_key(u"keyword");
    std::string encrypted_bytes = cipher.encrypt_raw_bytes(file_bytes);
    std::string decrypted_bytes = cipher.decrypt_raw_bytes(encrypted_bytes);
    std::string checksum1 = cr::sha256(file_bytes);
    std::string checksum2 = cr::sha256(decrypted_bytes);
    ASSERT_EQ(checksum1, checksum2);
}
