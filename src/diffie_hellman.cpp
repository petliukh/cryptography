#include "diffie_hellman.hpp"
#include "numeric_utils.hpp"

namespace petliukh::cryptography {

Diffie_hellman_public_pair diffie_hellman_generate_public_pair()
{
    return Diffie_hellman_public_pair{ big_random(30), big_random(30) };
}

BigInt diffie_hellman_share(
        const Diffie_hellman_public_pair& dh_pair, const BigInt& secret)
{
    return mod_exp(dh_pair.g, secret, dh_pair.p);
}

BigInt diffie_hellman_get_common_key(
        const BigInt& shared, const BigInt& secret,
        const BigInt& modulus)
{
    return mod_exp(shared, secret, modulus);
}

}  // namespace petliukh::cryptography
