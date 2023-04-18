#include "cipher_base.hpp"

#include <gtest/gtest.h>

namespace cr = petliukh::cryptography;

TEST(cipher_base_test, validates_message_correctly)
{
    std::u16string message = u"Hello, world! Привіт, світ! !@#!@#";

    cr::Language en = cr::Cipher::langs.at(u"EN");
    bool res = cr::validate_msg(message, en);
    EXPECT_FALSE(res);

    cr::Language ukr = cr::Cipher::langs.at(u"UKR");
    bool res2 = cr::validate_msg(message, ukr);
    EXPECT_FALSE(res2);
}

TEST(cipher_base_test, calculates_frequency_table_correctly)
{
    std::u16string message = u"Hello, world!";
    cr::Language en = cr::Cipher::langs.at(u"EN");

    auto freq_table = cr::count_chars(message, en);
    EXPECT_EQ(freq_table.at(u'H'), 1);
    EXPECT_EQ(freq_table.at(u'e'), 1);
    EXPECT_EQ(freq_table.at(u'l'), 3);
    EXPECT_EQ(freq_table.at(u'o'), 2);
    EXPECT_EQ(freq_table.at(u','), 1);
    EXPECT_EQ(freq_table.at(u' '), 1);
    EXPECT_EQ(freq_table.at(u'w'), 1);
    EXPECT_EQ(freq_table.at(u'r'), 1);
    EXPECT_EQ(freq_table.at(u'd'), 1);
    EXPECT_EQ(freq_table.at(u'!'), 1);

    std::u16string message2 = u"Привіт, світ!";
    cr::Language ukr = cr::Cipher::langs.at(u"UKR");

    auto freq_table2 = cr::count_chars(message2, ukr);
    EXPECT_EQ(freq_table2.at(u'П'), 1);
    EXPECT_EQ(freq_table2.at(u'р'), 1);
    EXPECT_EQ(freq_table2.at(u'и'), 1);
    EXPECT_EQ(freq_table2.at(u'в'), 2);
    EXPECT_EQ(freq_table2.at(u'і'), 2);
    EXPECT_EQ(freq_table2.at(u'т'), 2);
    EXPECT_EQ(freq_table2.at(u','), 1);
    EXPECT_EQ(freq_table2.at(u' '), 1);
    EXPECT_EQ(freq_table2.at(u'с'), 1);
    EXPECT_EQ(freq_table2.at(u'!'), 1);
}
