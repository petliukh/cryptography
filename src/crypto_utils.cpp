#include "crypto_utils.hpp"

#include "string_utils.hpp"

namespace petliukh::cryptography {
namespace su = petliukh::string_utils;

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
    return sha256(su::utf16_to_utf8(str));
}

}  // namespace petliukh::crypto_utils
