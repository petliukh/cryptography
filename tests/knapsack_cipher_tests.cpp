#include "knapsack_cipher.hpp"
#include "numeric_utils.hpp"
#include "crypto_utils.hpp"

#include <gtest/gtest.h>

namespace cr = petliukh::cryptography;

TEST(knapsack_test, test_supergrowing_seq_generated_correctly)
{
    std::vector<int64_t> supergrow_seq = cr::generate_superincreasing_sequence(16, 10000);
    int64_t prev_sum = 0;

    for (auto& e : supergrow_seq) {
        ASSERT_TRUE(e > prev_sum);
        prev_sum += e;
    }
}

TEST(knapsack_test, test_normal_knapsack_seq_generated_correctly)
{
    std::vector<int64_t> supergrow_seq = cr::generate_superincreasing_sequence(16, 10000);
    int64_t m = cr::generate_rand_m(supergrow_seq, 10000);
    int64_t t = cr::generate_rand_t(m);
    std::vector<int64_t> normal_knapsack_seq = cr::generate_normal_knapsack_sequence(
            supergrow_seq, m, t);

    for (int i = 0; i < supergrow_seq.size(); i++) {
        ASSERT_EQ((supergrow_seq[i] * t) % m, normal_knapsack_seq[i]);
    }
}

TEST(knapsack_test, encrypts_decrypts_correctly)
{
    cr::Knapsack_cipher kn;
    kn.set_max_growth(10000);
    kn.set_knapsack_size(16);
    kn.generate_random_key();

    std::u16string plaintext = u"Hello, world!";
    std::u16string ciphertext = kn.encrypt(plaintext);
    std::u16string decrypted_text = kn.decrypt(ciphertext);

    std::string cs1 = cr::sha256(plaintext);
    std::string cs2 = cr::sha256(decrypted_text);

    ASSERT_EQ(plaintext, decrypted_text);
    ASSERT_EQ(cs1, cs2);
}

TEST(knapsack_test, gcd_correctly)
{
    int32_t a = 1071;
    int32_t b = 462;
    int32_t d = cr::gcd(b, a);
    ASSERT_EQ(21, d);
}

TEST(knapsack_test, mod_inv_correctly)
{
    int32_t a = 240;
    int32_t m = 46;
    cr::Ext_euclidean_res<int32_t> res = cr::ext_euclidean(a, m);
    EXPECT_EQ(23, res.s);
}
