#include "trithemius_cipher.hpp"

#include <gtest/gtest.h>

namespace cr = petliukh::cryptography;
using tkey = cr::Trithemius_cipher::Key;
using tkey_type = cr::Trithemius_cipher::Key_type;

TEST(trithemius_test, sets_key_correctly)
{
    cr::Trithemius_cipher cipher;
    cipher.set_lang(u"EN");
    cipher.set_key(u"1,2");
    tkey key = cipher.get_key();
    ASSERT_EQ(key.type, tkey_type::v2);
    ASSERT_EQ(key.v2.x(), 1);
    ASSERT_EQ(key.v2.y(), 2);

    cipher.set_key(u"1,2,3");
    key = cipher.get_key();
    ASSERT_EQ(key.type, tkey_type::v3);
    ASSERT_EQ(key.v3.x(), 1);
    ASSERT_EQ(key.v3.y(), 2);
    ASSERT_EQ(key.v3.z(), 3);

    cipher.set_key(u"keyword");
    key = cipher.get_key();
    ASSERT_EQ(key.type, tkey_type::word);
    ASSERT_EQ(key.keyword, u"keyword");

    ASSERT_THROW(cipher.set_key(u"1,2,3,4"), std::invalid_argument);
    ASSERT_THROW(cipher.set_key(u"1,2,3,4,5"), std::invalid_argument);
    ASSERT_THROW(cipher.set_key(u"гасло"), std::invalid_argument);
}

TEST(trithemius_test, encrypts_decrypts_v2_correctly)
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

TEST(trithemius_test, encrypts_decrypts_v3_correctly)
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

TEST(trithemius_test, encrypts_decrypts_kw_correctly)
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

TEST(trithemius_test, encrypts_decrypts_raw_bytes_v2_correctly)
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

TEST(trithemius_test, encrypts_decrypts_raw_bytes_v3_correctly)
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

TEST(trithemius_test, encrypts_decrypts_raw_bytes_kw_correctly)
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

TEST(trithemius_test, breaks_key_by_msg_pair_correctly_v2) {
    cr::Trithemius_cipher cipher;
    cipher.set_lang(u"EN");
    cipher.set_key(u"2,3");
    tkey my_key = cipher.get_key();
    std::u16string message = u"Hello, World!";
    std::u16string encrypted = cipher.encrypt(message);

    tkey key = cipher.break_cipher(encrypted, message);
    ASSERT_EQ(key.v2.x(), my_key.v2.x());
    ASSERT_EQ(key.v2.y(), my_key.v2.y());

    cipher.set_key(u"8,6");
    my_key = cipher.get_key();
    encrypted = cipher.encrypt(message);

    key = cipher.break_cipher(encrypted, message);
    ASSERT_EQ(key.v2.x(), my_key.v2.x());
    ASSERT_EQ(key.v2.y(), my_key.v2.y());

    cipher.set_key(u"19,24");
    my_key = cipher.get_key();
    encrypted = cipher.encrypt(message);

    key = cipher.break_cipher(encrypted, message);
    ASSERT_EQ(key.v2.x(), my_key.v2.x());
    ASSERT_EQ(key.v2.y(), my_key.v2.y());

    cipher.set_key(u"16,9");
    my_key = cipher.get_key();
    encrypted = cipher.encrypt(message);

    key = cipher.break_cipher(encrypted, message);
    ASSERT_EQ(key.v2.x(), my_key.v2.x());
    ASSERT_EQ(key.v2.y(), my_key.v2.y());
}

TEST(trithemius_test, breaks_key_by_msg_pair_correctly_v3) {
    cr::Trithemius_cipher cipher;
    cipher.set_lang(u"EN");
    cipher.set_key(u"2,3,5");
    tkey my_key = cipher.get_key();
    std::u16string message = u"Hello, World!";
    std::u16string encrypted = cipher.encrypt(message);

    tkey key = cipher.break_cipher(encrypted, message);
    ASSERT_EQ(key.v3.x(), my_key.v3.x());
    ASSERT_EQ(key.v3.y(), my_key.v3.y());
    ASSERT_EQ(key.v3.z(), my_key.v3.z());

    cipher.set_key(u"8,6,7");
    my_key = cipher.get_key();
    encrypted = cipher.encrypt(message);

    key = cipher.break_cipher(encrypted, message);
    ASSERT_EQ(key.v3.x(), my_key.v3.x());
    ASSERT_EQ(key.v3.y(), my_key.v3.y());
    ASSERT_EQ(key.v3.z(), my_key.v3.z());

    cipher.set_key(u"19,24,15");
    my_key = cipher.get_key();
    encrypted = cipher.encrypt(message);

    key = cipher.break_cipher(encrypted, message);
    ASSERT_EQ(key.v3.x(), my_key.v3.x());
    ASSERT_EQ(key.v3.y(), my_key.v3.y());
    ASSERT_EQ(key.v3.z(), my_key.v3.z());

    cipher.set_key(u"16,9,11");
    my_key = cipher.get_key();
    encrypted = cipher.encrypt(message);

    key = cipher.break_cipher(encrypted, message);
    ASSERT_EQ(key.v3.x(), my_key.v3.x());
    ASSERT_EQ(key.v3.y(), my_key.v3.y());
    ASSERT_EQ(key.v3.z(), my_key.v3.z());
}
