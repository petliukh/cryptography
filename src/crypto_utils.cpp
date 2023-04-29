#include "crypto_utils.hpp"

#include "string_utils.hpp"

#include <chrono>
#include <cstdlib>
#include <openssl/sha.h>

namespace petliukh::cryptography {

std::string sha256(const std::string& str)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*) str.c_str(), str.length(), digest);
    char hex_digest[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex_digest + i * 2, "%02x", digest[i]);
    }
    hex_digest[SHA256_DIGEST_LENGTH * 2] = '\0';
    return std::string(hex_digest);
}

std::string sha256(const std::u16string& str)
{
    return sha256(utf16_to_utf8(str));
}

int randint(int a, int b)
{
    auto now = std::chrono::high_resolution_clock::now();
    size_t seed = static_cast<size_t>(now.time_since_epoch().count());
    std::srand(seed);
    return (std::rand() + a) % b;
}

InfInt infint_rand(size_t num_digits)
{
    std::string big_rand;
    big_rand.reserve(num_digits);
    big_rand += '1' + (std::rand() % 9);
    for (size_t i = 1; i < num_digits; i++) {
        big_rand += '0' + (std::rand() % 10);
    }
    return InfInt(big_rand);
}

}  // namespace petliukh::cryptography
