#include "crypto_utils.hpp"
#include "trithemius_cipher.hpp"

#include <fstream>
#include <gtest/gtest.h>

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

TEST(trithemius_test, breaks_key_by_msg_pair_correctly_vec2)
{
    cr::Trithemius_cipher cipher;
    cipher.set_lang(u"EN");
    cipher.set_key(u"2,3");
    T_key my_key = cipher.get_key();
    std::u16string message = u"Hello, World!";
    std::u16string encrypted = cipher.encrypt(message);

    T_key key = cipher.break_cipher_with_msg_pair(encrypted, message, 3);
    ASSERT_EQ(key.vec.x(), my_key.vec.x());
    ASSERT_EQ(key.vec.y(), my_key.vec.y());

    cipher.set_key(u"8,6");
    my_key = cipher.get_key();
    encrypted = cipher.encrypt(message);

    key = cipher.break_cipher_with_msg_pair(encrypted, message, 3);
    ASSERT_EQ(key.vec.x(), my_key.vec.x());
    ASSERT_EQ(key.vec.y(), my_key.vec.y());

    cipher.set_key(u"19,24");
    my_key = cipher.get_key();
    encrypted = cipher.encrypt(message);

    key = cipher.break_cipher_with_msg_pair(encrypted, message, 3);
    ASSERT_EQ(key.vec.x(), my_key.vec.x());
    ASSERT_EQ(key.vec.y(), my_key.vec.y());

    cipher.set_key(u"16,9");
    my_key = cipher.get_key();
    encrypted = cipher.encrypt(message);

    key = cipher.break_cipher_with_msg_pair(encrypted, message, 3);
    ASSERT_EQ(key.vec.x(), my_key.vec.x());
    ASSERT_EQ(key.vec.y(), my_key.vec.y());
}

TEST(trithemius_test, breaks_key_by_msg_pair_correctly_vec3)
{
    cr::Trithemius_cipher cipher;
    cipher.set_lang(u"EN");
    cipher.set_key(u"2,3,5");
    T_key my_key = cipher.get_key();
    std::u16string message = u"Hello, World!";
    std::u16string encrypted = cipher.encrypt(message);

    T_key key = cipher.break_cipher_with_msg_pair(encrypted, message, 3);
    ASSERT_EQ(key.vec.x(), my_key.vec.x());
    ASSERT_EQ(key.vec.y(), my_key.vec.y());
    ASSERT_EQ(key.vec.z(), my_key.vec.z());

    cipher.set_key(u"8,6,7");
    my_key = cipher.get_key();
    encrypted = cipher.encrypt(message);

    key = cipher.break_cipher_with_msg_pair(encrypted, message, 3);
    ASSERT_EQ(key.vec.x(), my_key.vec.x());
    ASSERT_EQ(key.vec.y(), my_key.vec.y());
    ASSERT_EQ(key.vec.z(), my_key.vec.z());

    cipher.set_key(u"19,24,15");
    my_key = cipher.get_key();
    encrypted = cipher.encrypt(message);

    key = cipher.break_cipher_with_msg_pair(encrypted, message, 3);
    ASSERT_EQ(key.vec.x(), my_key.vec.x());
    ASSERT_EQ(key.vec.y(), my_key.vec.y());
    ASSERT_EQ(key.vec.z(), my_key.vec.z());

    cipher.set_key(u"16,9,11");
    my_key = cipher.get_key();
    encrypted = cipher.encrypt(message);

    key = cipher.break_cipher_with_msg_pair(encrypted, message, 3);
    ASSERT_EQ(key.vec.x(), my_key.vec.x());
    ASSERT_EQ(key.vec.y(), my_key.vec.y());
    ASSERT_EQ(key.vec.z(), my_key.vec.z());
}

TEST(trithemius_test, breaks_key_by_freq_table_correctly)
{
    std::u16string large_plaintext
            = u"In the heart of the dense jungle, a majestic tiger roamed "
              u"freely, his coat"
              "glistening in the sun as he stalked his prey. The birds above "
              "chirped in alarm"
              "as the tiger approached, their feathers ruffled by the gusts of "
              "wind. Suddenly,"
              "the tiger pounced, his powerful legs propelling him forward "
              "with lightning"
              "speed. His prey, a small deer, was no match for his strength "
              "and agility,"
              "and he quickly dispatched it with a swift bite to the neck.\n"
              "As the tiger savored his meal, he couldn't help but feel a "
              "sense of pride and"
              "accomplishment. He was the king of the jungle, feared and "
              "respected by all who"
              "crossed his path. But even the mightiest of creatures had their "
              "weaknesses, and"
              "the tiger knew that he was not invincible. He had to be "
              "vigilant at all times,"
              "always on the lookout for danger.\n"
              "As the sun began to set, the tiger made his way back to his "
              "lair, a secluded"
              "den deep in the heart of the jungle. There, he would rest and "
              "recharge, ready"
              "to face whatever challenges lay ahead. For the jungle was a "
              "wild and"
              "unpredictable place, full of both beauty and danger, and only "
              "the strongest"
              "and most resilient could survive.\n"
              "And so the tiger slept, his powerful body at ease, dreaming of "
              "the adventures"
              "that awaited him in the days and weeks to come. For he was a "
              "creature of the"
              "wild, born to roam free and rule the jungle with an iron paw. "
              "And nothing"
              "could stand in his way.";

    std::map<char16_t, double> en_freqs{
        { u'a', 0.08167 }, { u'b', 0.01492 }, { u'c', 0.02782 },
        { u'd', 0.04253 }, { u'e', 0.12702 }, { u'f', 0.02228 },
        { u'g', 0.02015 }, { u'h', 0.06094 }, { u'i', 0.06966 },
        { u'j', 0.00153 }, { u'k', 0.00772 }, { u'l', 0.04025 },
        { u'm', 0.02406 }, { u'n', 0.06749 }, { u'o', 0.07507 },
        { u'p', 0.01929 }, { u'q', 0.00095 }, { u'r', 0.05987 },
        { u's', 0.06327 }, { u't', 0.09056 }, { u'u', 0.02758 },
        { u'v', 0.00978 }, { u'w', 0.0236 },  { u'x', 0.0015 },
        { u'y', 0.01974 }, { u'z', 0.00074 }
    };

    cr::Trithemius_cipher trit;
    trit.set_key(u"9,12,7");
    std::u16string enc = trit.encrypt(large_plaintext);
    std::map<std::u16string, std::u16string> tries
            = trit.break_cipher_with_freqs(en_freqs, enc, 200, 3);
    std::string checksum1 = cr::sha256(large_plaintext);

    bool any = false;
    for (auto& [key, msg] : tries) {
        std::string checksum2 = cr::sha256(msg);
        any |= (checksum1 == checksum2);
    }
    EXPECT_TRUE(any);
}
