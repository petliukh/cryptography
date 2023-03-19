#include "cipher_base.hpp"

namespace petliukh::cryptography {

std::string utf16_to_utf8(const std::u16string& utf16) {
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> conv;
    std::string utf8 = conv.to_bytes(utf16);
    return utf8;
}

std::u16string utf8_to_utf16(const std::string& utf8) {
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> conv;
    std::u16string utf16 = conv.from_bytes(utf8);
    return utf16;
}

std::unordered_map<char16_t, int>
get_message_freqs(const std::u16string& message, const language& lang) {
    std::unordered_map<char16_t, int> freqs;
    freqs.reserve(lang.alphabet.size());
    for (char16_t c : message) {
        if (lang.alphabet.find(c) != std::u16string::npos) {
            freqs[c]++;
        }
    }
    return freqs;
}

bool validate_message(
        const std::u16string& message, const std::u16string& lang) {
    language lang_ = languages.at(lang);
    for (char16_t c : message) {
        if (lang_.alphabet.find(c) == std::u16string::npos) {
            return false;
        }
    }
    return true;
}

bool validate_message(const std::u16string& message, const language& lang) {
    for (char16_t c : message) {
        if (lang.alphabet.find(c) == std::u16string::npos) {
            return false;
        }
    }
    return true;
}

std::string sha256(const std::string& str) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*) str.c_str(), str.length(), digest);
    char hex_digest[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex_digest + i * 2, "%02x", digest[i]);
    }
    hex_digest[SHA256_DIGEST_LENGTH * 2] = '\0';
    return std::string(hex_digest);
}

std::string sha256(const std::u16string& str) {
    return sha256(utf16_to_utf8(str));
}

}  // namespace petliukh::cryptography
