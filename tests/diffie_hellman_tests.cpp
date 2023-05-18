#include "diffie_hellman.hpp"
#include <gtest/gtest.h>

namespace cr = petliukh::cryptography;

TEST(diffie_hellman, test_key_exchange)
{
    cr::Diffie_hellman_public_pair dh_pair = cr::diffie_hellman_generate_public_pair();
    BigInt a = big_random(30);
    BigInt b = big_random(30);

    BigInt A = cr::diffie_hellman_share(dh_pair, a);
    BigInt B = cr::diffie_hellman_share(dh_pair, b);

    BigInt K1 = cr::diffie_hellman_get_common_key(A, b, dh_pair.p);
    BigInt K2 = cr::diffie_hellman_get_common_key(B, a, dh_pair.p);

    EXPECT_EQ(K1, K2);
}
