#include "BigInt.hpp"

namespace petliukh::cryptography {

struct Diffie_hellman_public_pair {
    BigInt g;
    BigInt p;
};

Diffie_hellman_public_pair diffie_hellman_generate_public_pair();
BigInt diffie_hellman_share(
        const Diffie_hellman_public_pair& dh_pair, const BigInt& secret);
BigInt diffie_hellman_get_common_key(
        const BigInt& shared, const BigInt& secret, const BigInt& modulus);

}  // namespace petliukh::cryptography
