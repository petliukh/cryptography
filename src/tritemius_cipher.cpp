#include "tritemius_cipher.hpp"

namespace petliukh::cryptography {

tritemius_cipher::tritemius_cipher() {
}

std::u16string tritemius_cipher::encrypt(const std::u16string& message) {
    return std::u16string();
}

std::u16string tritemius_cipher::decrypt(const std::u16string& message) {
    return std::u16string();
}

std::string tritemius_cipher::encrypt_raw_bytes(const std::string& bytes) {
    return std::string();
}

std::string tritemius_cipher::decrypt_raw_bytes(const std::string& bytes) {
    return std::string();
}

void tritemius_cipher::set_key(const std::u16string& key) {
}

void tritemius_cipher::set_lang(const std::u16string& lang) {
}

void tritemius_cipher::set_lang(const language& lang) {
}

}  // namespace petliukh::cryptography
