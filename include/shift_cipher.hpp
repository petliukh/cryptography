#pragma once

#include <string>
#include <unordered_map>
#include <vector>

namespace petliukh::cryptography {

struct language {
    std::u16string code;
    std::u16string name;
    std::u16string alphabet;
};

struct message {
    std::u16string text;
    int key;
};

class shift_cipher {
public:
    static const std::u16string special_chars;

    static const std::unordered_map<std::u16string, language> languages;

    shift_cipher();

    shift_cipher(language lang, int max_data_size = 1000);

    shift_cipher(std::u16string lang, int max_data_size = 1000);

    std::u16string encrypt_text(const std::u16string& plaintext, int key) const;

    void encrypt_file(
            const std::string& input_file, int key,
            const std::string& output_file = "") const;

    std::u16string
    decrypt_text(const std::u16string& ciphertext, int key) const;

    void decrypt_file(
            const std::string& input_file, int key,
            const std::string& output_file = "") const;

    std::vector<message> brute_force(const std::u16string& ciphertext) const;

    void validate_key(int key) const;

    void validate_message(const std::u16string& message) const;

    std::unordered_map<char16_t, int>
    get_frequency(const std::u16string& text) const;

private:
    language m_lang;
    int m_max_msg_length;
};
}  // namespace petliukh::cryptography
