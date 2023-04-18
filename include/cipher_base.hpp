#pragma once
#include <string>
#include <unordered_map>

namespace petliukh::cryptography {

struct Language {
    std::u16string code;
    std::u16string name;
    std::u16string alphabet;
};

class Cipher {
public:
    static const std::u16string special_chars;
    static const std::unordered_map<std::u16string, Language> langs;

    virtual ~Cipher() = default;
    virtual std::u16string encrypt(const std::u16string& message) = 0;
    virtual std::u16string decrypt(const std::u16string& message) = 0;
    virtual std::string encrypt_raw_bytes(const std::string& bytes) = 0;
    virtual std::string decrypt_raw_bytes(const std::string& bytes) = 0;
    virtual void set_key(const std::u16string& key) = 0;
    virtual void set_lang(const std::u16string& lang) = 0;
    virtual void set_lang(const Language& lang) = 0;
};

bool validate_msg(const std::u16string& msg, const Language& lang);
bool validate_msg(const std::u16string& msg, std::u16string& lang);
std::unordered_map<char16_t, int> count_chars(
        const std::u16string& msg, const Language& lang);

}  // namespace petliukh::cryptography
