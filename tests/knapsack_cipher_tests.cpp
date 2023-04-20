#include "knapsack_cipher.hpp"

#include <gtest/gtest.h>

namespace cr = petliukh::cryptography;

TEST(knapsack_test, test_supergrowing_seq_generated_correctly)
{
    std::vector<size_t> supergrow_seq = cr::generate_supergrowing_sequence(10);
    int prev_sum = 0;

    for (auto& e : supergrow_seq) {
        ASSERT_TRUE(e > prev_sum);
        prev_sum += e;
    }
}
