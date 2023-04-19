#include "trithemius_cipher.hpp"
#include "crypto_utils.hpp"

#include <gtest/gtest.h>
#include <fstream>

namespace cr = petliukh::cryptography;
using T_key = cr::Trithemius_cipher::Key;
using T_key_type = cr::Trithemius_cipher::Key_type;

TEST(trithemius_test, sets_key_correctly)
{
    cr::Trithemius_cipher cipher;
    cipher.set_lang(u"EN");
    cipher.set_key(u"1,2");
    T_key key = cipher.get_key();
    ASSERT_EQ(key.type, T_key_type::vec);
    ASSERT_EQ(key.vec.x(), 1);
    ASSERT_EQ(key.vec.y(), 2);

    cipher.set_key(u"1,2,3");
    key = cipher.get_key();
    ASSERT_EQ(key.type, T_key_type::vec);
    ASSERT_EQ(key.vec.x(), 1);
    ASSERT_EQ(key.vec.y(), 2);
    ASSERT_EQ(key.vec.z(), 3);

    cipher.set_key(u"keyword");
    key = cipher.get_key();
    ASSERT_EQ(key.type, T_key_type::word);
    ASSERT_EQ(key.keyword, u"keyword");

    ASSERT_THROW(cipher.set_key(u"1,2,3,4"), std::invalid_argument);
    ASSERT_THROW(cipher.set_key(u"1,2,3,4,5"), std::invalid_argument);
    ASSERT_THROW(cipher.set_key(u"гасло"), std::invalid_argument);
}

TEST(trithemius_test, encrypts_decrypts_vec2_correctly)
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

TEST(trithemius_test, encrypts_decrypts_vec3_correctly)
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

TEST(trithemius_test, encrypts_decrypts_raw_bytes_vec2_correctly)
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

TEST(trithemius_test, encrypts_decrypts_raw_bytes_vec3_correctly)
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

TEST(trithemius_test, breaks_key_by_msg_pair_correctly_vec2) {
    cr::Trithemius_cipher cipher;
    cipher.set_lang(u"EN");
    cipher.set_key(u"2,3");
    T_key my_key = cipher.get_key();
    std::u16string message = u"Hello, World!";
    std::u16string encrypted = cipher.encrypt(message);

    T_key key = cipher.break_cipher(encrypted, message);
    ASSERT_EQ(key.vec.x(), my_key.vec.x());
    ASSERT_EQ(key.vec.y(), my_key.vec.y());

    cipher.set_key(u"8,6");
    my_key = cipher.get_key();
    encrypted = cipher.encrypt(message);

    key = cipher.break_cipher(encrypted, message);
    ASSERT_EQ(key.vec.x(), my_key.vec.x());
    ASSERT_EQ(key.vec.y(), my_key.vec.y());

    cipher.set_key(u"19,24");
    my_key = cipher.get_key();
    encrypted = cipher.encrypt(message);

    key = cipher.break_cipher(encrypted, message);
    ASSERT_EQ(key.vec.x(), my_key.vec.x());
    ASSERT_EQ(key.vec.y(), my_key.vec.y());

    cipher.set_key(u"16,9");
    my_key = cipher.get_key();
    encrypted = cipher.encrypt(message);

    key = cipher.break_cipher(encrypted, message);
    ASSERT_EQ(key.vec.x(), my_key.vec.x());
    ASSERT_EQ(key.vec.y(), my_key.vec.y());
}

TEST(trithemius_test, breaks_key_by_msg_pair_correctly_vec3) {
    cr::Trithemius_cipher cipher;
    cipher.set_lang(u"EN");
    cipher.set_key(u"2,3,5");
    T_key my_key = cipher.get_key();
    std::u16string message = u"Hello, World!";
    std::u16string encrypted = cipher.encrypt(message);

    T_key key = cipher.break_cipher(encrypted, message);
    ASSERT_EQ(key.vec.x(), my_key.vec.x());
    ASSERT_EQ(key.vec.y(), my_key.vec.y());
    ASSERT_EQ(key.vec.z(), my_key.vec.z());

    cipher.set_key(u"8,6,7");
    my_key = cipher.get_key();
    encrypted = cipher.encrypt(message);

    key = cipher.break_cipher(encrypted, message);
    ASSERT_EQ(key.vec.x(), my_key.vec.x());
    ASSERT_EQ(key.vec.y(), my_key.vec.y());
    ASSERT_EQ(key.vec.z(), my_key.vec.z());

    cipher.set_key(u"19,24,15");
    my_key = cipher.get_key();
    encrypted = cipher.encrypt(message);

    key = cipher.break_cipher(encrypted, message);
    ASSERT_EQ(key.vec.x(), my_key.vec.x());
    ASSERT_EQ(key.vec.y(), my_key.vec.y());
    ASSERT_EQ(key.vec.z(), my_key.vec.z());

    cipher.set_key(u"16,9,11");
    my_key = cipher.get_key();
    encrypted = cipher.encrypt(message);

    key = cipher.break_cipher(encrypted, message);
    ASSERT_EQ(key.vec.x(), my_key.vec.x());
    ASSERT_EQ(key.vec.y(), my_key.vec.y());
    ASSERT_EQ(key.vec.z(), my_key.vec.z());
}
