#include "shift_cipher.hpp"

#include "string_utils.hpp"

#include <stdexcept>

namespace petliukh::cryptography {

Shift_cipher::Shift_cipher() : m_key(0), m_lang(Cipher::langs.at(u"EN"))
{
}

std::u16string Shift_cipher::encrypt(const std::u16string& message)
{
    return encrypt_(message, m_key);
}

std::u16string Shift_cipher::decrypt(const std::u16string& message)
{
    return decrypt_(message, m_key);
}

std::string Shift_cipher::encrypt_raw_bytes(const std::string& bytes)
{
    return encrypt_raw_bytes_(bytes, m_key);
}

std::string Shift_cipher::decrypt_raw_bytes(const std::string& bytes)
{
    return decrypt_raw_bytes_(bytes, m_key);
}

void Shift_cipher::set_key(const std::u16string& key)
{
    std::string key_str = utf16_to_utf8(key);
    int ikey = std::stoi(key_str);

    if (ikey < 0 || ikey >= m_lang.alphabet.size()) {
        throw std::invalid_argument("Invalid key");
    }

    m_key = ikey;
}

void Shift_cipher::set_key(int key)
{
    if (key < 0 || key >= m_lang.alphabet.size()) {
        throw std::invalid_argument("Invalid key");
    }

    m_key = key;
}

void Shift_cipher::set_lang(const std::u16string& lang)
{
    m_lang = Cipher::langs.at(lang);
}

void Shift_cipher::set_lang(const Language& lang)
{
    m_lang = lang;
}

int Shift_cipher::get_key() const
{
    return m_key;
}

std::map<int, std::u16string>
Shift_cipher::brute_force(const std::u16string& message)
{
    std::map<int, std::u16string> messages;

    for (int key = 0; key < m_lang.alphabet.size(); key++) {
        std::u16string decrypted_msg = decrypt_(message, key);
        messages[key] = decrypted_msg;
    }

    return messages;
}

std::u16string Shift_cipher::encrypt_(const std::u16string& message, int key)
{
    std::u16string output;
    for (char16_t c : message) {
        int pos = m_lang.alphabet.find(c);
        if (pos != std::u16string::npos) {
            pos = (pos + key) % m_lang.alphabet.size();
            output += m_lang.alphabet[pos];
        } else {
            output += c;
        }
    }
    return output;
}

std::u16string Shift_cipher::decrypt_(const std::u16string& message, int key)
{
    return encrypt_(message, m_lang.alphabet.size() - key);
}

std::string Shift_cipher::encrypt_raw_bytes_(const std::string& bytes, int key)
{
    std::string output;
    output.reserve(bytes.size());

    for (char c : bytes) {
        output += static_cast<char>(
                (static_cast<unsigned char>(c) + key) % 256);
    }

    return output;
}

std::string Shift_cipher::decrypt_raw_bytes_(const std::string& bytes, int key)
{
    return encrypt_raw_bytes_(bytes, 256 - key);
}

}  // namespace petliukh::cryptography
