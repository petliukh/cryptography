#include "crypto_utils.hpp"
#include "knapsack_cipher.hpp"
#include "numeric_utils.hpp"
#include "string_utils.hpp"

#include <bitset>
#include <gtest/gtest.h>
#include <iostream>

namespace cr = petliukh::cryptography;

TEST(knapsack_cipher, superincreasing_sequence)
{
    std::vector<BigInt> superinc_seq
            = cr::generate_superincreasing_sequence(16, 64, 64);

    BigInt sum = superinc_seq[0];
    for (size_t i = 1; i < superinc_seq.size(); i++) {
        ASSERT_TRUE(superinc_seq[i] > sum);
        sum += superinc_seq[i];
    }
}

TEST(knapsack_cipher, knapsack_sequence)
{
    std::vector<BigInt> superinc_seq
            = cr::generate_superincreasing_sequence(16, 64, 64);
    BigInt m = cr::generate_rand_modulus(superinc_seq, 64);
    BigInt t = cr::generate_rand_multiplier(m);
    std::vector<BigInt> knapsack_seq
            = cr::generate_knapsack_sequence(superinc_seq, m, t);

    for (size_t i = 0; i < superinc_seq.size(); i++) {
        ASSERT_EQ(knapsack_seq[i], (superinc_seq[i] * t) % m);
    }
}

TEST(knapsack_cipher, encryption_algorithm_logic)
{
    std::vector<BigInt> superinc_seq
            = cr::generate_superincreasing_sequence(16, 64, 64);
    BigInt m = cr::generate_rand_modulus(superinc_seq, 64);
    BigInt t = cr::generate_rand_multiplier(m);
    std::vector<BigInt> knapsack_seq
            = cr::generate_knapsack_sequence(superinc_seq, m, t);

    std::cout << "Superincreasing sequence:\n"
              << cr::vec_to_string(superinc_seq) << "\n";

    std::cout << "Knapsack sequence:\n"
              << cr::vec_to_string(knapsack_seq) << "\n";

    std::u16string msg = u"abcdefg";

    for (auto chr : msg) {
        BigInt ciphertext = 0;
        for (size_t i = 0; i < 16; i++) {
            if (chr & (1 << i)) {
                ciphertext += knapsack_seq[i];
            }
        }

        std::cout << ciphertext << "\n";
        std::cout << std::bitset<16>(chr) << "\n";

        BigInt t_inv = cr::mod_inverse(t, m);
        BigInt c_prime = (ciphertext * t_inv) % m;

        char16_t sol = cr::solve_knapsack(superinc_seq, c_prime);
        std::cout << std::bitset<16>(sol) << "\n";

        EXPECT_EQ(chr, sol);
    }
}

TEST(knapsack_sequence, encrypts_decrypts_correctly)
{
    cr::Knapsack_cipher ks;
    ks.generate_rand_key(20);

    std::u16string message = u"Hello, World!";
    std::u16string encrypted = ks.encrypt(message);
    std::u16string decrypted = ks.decrypt(encrypted);

    std::string checksum1 = cr::sha256(message);
    std::string checksum2 = cr::sha256(decrypted);

    ASSERT_EQ(message, decrypted);
}

TEST(knapsack_sequence, encrypts_decrypts_correctly_bytes)
{
    cr::Knapsack_cipher ks;
    ks.generate_rand_key(20);

    std::string bytes
            = "asdasasndklkbakbvklabіфлаиівалифілварифілв"
              "akjsfdblgdbalib vfa sdkn asvkasivhdba sih"
              "уоифівиалфів доівмлфівм ілвфлів мфлівимф";
    std::string encrypted = ks.encrypt_raw_bytes(bytes);
    std::string decrypted = ks.decrypt_raw_bytes(encrypted);

    std::string checksum1 = cr::sha256(bytes);
    std::string checksum2 = cr::sha256(decrypted);

    ASSERT_EQ(bytes, decrypted);
}
