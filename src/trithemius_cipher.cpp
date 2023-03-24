#include "trithemius_cipher.hpp"

namespace petliukh::cryptography {

Trithemius_cipher::Trithemius_cipher() : m_lang(languages.at(u"EN"))
{
}

std::u16string Trithemius_cipher::encrypt(const std::u16string& message)
{
    switch (m_key.type) {
    case key_type::v2:
        return encrypt_v2(message);
    case key_type::v3:
        return encrypt_v3(message);
    case key_type::word:
        return encrypt_kw(message);
    default:
        throw std::invalid_argument("Invalid key");
    }
}

std::u16string Trithemius_cipher::decrypt(const std::u16string& message)
{
    switch (m_key.type) {
    case key_type::v2:
        return decrypt_v2(message);
    case key_type::v3:
        return decrypt_v3(message);
    case key_type::word:
        return decrypt_kw(message);
    default:
        throw std::invalid_argument("Invalid key");
    }
}

std::string Trithemius_cipher::encrypt_raw_bytes(const std::string& bytes)
{
    switch (m_key.type) {
    case key_type::v2:
        return encrypt_raw_bytes_v2(bytes);
    case key_type::v3:
        return encrypt_raw_bytes_v3(bytes);
    case key_type::word:
        return encrypt_raw_bytes_kw(bytes);
    default:
        throw std::invalid_argument("Invalid key");
    }
}

std::string Trithemius_cipher::decrypt_raw_bytes(const std::string& bytes)
{
    switch (m_key.type) {
    case key_type::v2:
        return decrypt_raw_bytes_v2(bytes);
    case key_type::v3:
        return decrypt_raw_bytes_v3(bytes);
    case key_type::word:
        return decrypt_raw_bytes_kw(bytes);
    default:
        throw std::invalid_argument("Invalid key");
    }
}

void Trithemius_cipher::set_key(const std::u16string& key)
{
    auto key_parts = ssplit(utf16_to_utf8(key), ',');
    std::vector<int32_t> key_parts_num;

    for (const auto& part : key_parts) {
        try {
            key_parts_num.push_back(std::stoi(part));
        } catch (const std::invalid_argument& e) {
            std::u16string keyword = utf8_to_utf16(part);
            if (!validate_keyword(keyword)) {
                throw std::invalid_argument("Invalid key");
            }
            m_key.type = key_type::word;
            m_key.keyword = keyword;
            return;
        }
    }

    if (key_parts_num.size() == 2) {
        m_key.type = key_type::v2;
        m_key.key_v2 = egn::Vector2i(key_parts_num[0], key_parts_num[1]);
    } else if (key_parts_num.size() == 3) {
        m_key.type = key_type::v3;
        m_key.key_v3 = egn::Vector3i(
                key_parts_num[0], key_parts_num[1], key_parts_num[2]);
    } else {
        throw std::invalid_argument("Invalid key");
    }
}

Trithemius_cipher::key Trithemius_cipher::get_key() const
{
    return m_key;
}

void Trithemius_cipher::set_lang(const std::u16string& lang)
{
    m_lang = languages.at(lang);
}

void Trithemius_cipher::set_lang(const language& lang)
{
    m_lang = lang;
}

bool Trithemius_cipher::validate_keyword(const std::u16string& keyword)
{
    for (auto c : keyword) {
        if (m_lang.alphabet.find(c) == std::string::npos) {
            return false;
        }
    }
    return true;
}

std::u16string Trithemius_cipher::encrypt_v2(const std::u16string& message)
{
    std::u16string output;
    for (int i = 0; i < message.size(); ++i) {
        int x = m_lang.alphabet.find(message[i]);
        if (x == std::string::npos) {
            output += message[i];
            continue;
        }
        int k = m_key.key_v2.x() * i + m_key.key_v2.y();
        int y = (x + k) % m_lang.alphabet.size();
        output += m_lang.alphabet[y];
    }
    return output;
}

std::u16string Trithemius_cipher::decrypt_v2(const std::u16string& message)
{
    std::u16string output;
    for (int i = 0; i < message.size(); i++) {
        int y = m_lang.alphabet.find(message[i]);
        if (y == std::string::npos) {
            output += message[i];
            continue;
        }
        int k = m_key.key_v2.x() * i + m_key.key_v2.y();
        int n = m_lang.alphabet.size();
        int x = (y + n - (k % n)) % n;
        output += m_lang.alphabet[x];
    }
    return output;
}

std::u16string Trithemius_cipher::encrypt_v3(const std::u16string& message)
{
    std::u16string output;
    for (int i = 0; i < message.size(); ++i) {
        int x = m_lang.alphabet.find(message[i]);
        if (x == std::string::npos) {
            output += message[i];
            continue;
        }
        int k = m_key.key_v3.x() * i * i + m_key.key_v3.y() * i
                + m_key.key_v3.z();
        int y = (x + k) % m_lang.alphabet.size();
        output += m_lang.alphabet[y];
    }
    return output;
}

std::u16string Trithemius_cipher::decrypt_v3(const std::u16string& message)
{
    std::u16string output;
    for (int i = 0; i < message.size(); i++) {
        int y = m_lang.alphabet.find(message[i]);
        if (y == std::string::npos) {
            output += message[i];
            continue;
        }
        int k = m_key.key_v3.x() * i * i + m_key.key_v3.y() * i
                + m_key.key_v3.z();
        int n = m_lang.alphabet.size();
        int x = (y + n - (k % n)) % n;
        output += m_lang.alphabet[x];
    }
    return output;
}

std::u16string Trithemius_cipher::encrypt_kw(const std::u16string& message)
{
    std::u16string output;
    for (int i = 0; i < message.size(); ++i) {
        int x = m_lang.alphabet.find(message[i]);
        if (x == std::string::npos) {
            output += message[i];
            continue;
        }
        int k = m_lang.alphabet.find(m_key.keyword[i % m_key.keyword.size()]);
        int y = (x + k) % m_lang.alphabet.size();
        output += m_lang.alphabet[y];
    }
    return output;
}

std::u16string Trithemius_cipher::decrypt_kw(const std::u16string& message)
{
    std::u16string output;
    for (int i = 0; i < message.size(); i++) {
        int y = m_lang.alphabet.find(message[i]);
        if (y == std::string::npos) {
            output += message[i];
            continue;
        }
        int k = m_lang.alphabet.find(m_key.keyword[i % m_key.keyword.size()]);
        int n = m_lang.alphabet.size();
        int x = (y + n - (k % n)) % n;
        output += m_lang.alphabet[x];
    }
    return output;
}

std::string Trithemius_cipher::encrypt_raw_bytes_v2(const std::string& message)
{
    std::string output;
    for (int i = 0; i < message.size(); ++i) {
        int x = message[i];
        int k = m_key.key_v2.x() * i + m_key.key_v2.y();
        int y = (x + k) % 256;
        output += static_cast<char>(y);
    }
    return output;
}

std::string Trithemius_cipher::decrypt_raw_bytes_v2(const std::string& message)
{
    std::string output;
    for (int i = 0; i < message.size(); i++) {
        int y = message[i];
        int k = m_key.key_v2.x() * i + m_key.key_v2.y();
        int n = 256;
        int x = (y + n - (k % n)) % n;
        output += static_cast<char>(x);
    }
    return output;
}

std::string Trithemius_cipher::encrypt_raw_bytes_v3(const std::string& message)
{
    std::string output;
    for (int i = 0; i < message.size(); ++i) {
        int x = message[i];
        int k = m_key.key_v3.x() * i * i + m_key.key_v3.y() * i
                + m_key.key_v3.z();
        int y = (x + k) % 256;
        output += static_cast<char>(y);
    }
    return output;
}

std::string Trithemius_cipher::decrypt_raw_bytes_v3(const std::string& message)
{
    std::string output;
    for (int i = 0; i < message.size(); i++) {
        int y = message[i];
        int k = m_key.key_v3.x() * i * i + m_key.key_v3.y() * i
                + m_key.key_v3.z();
        int n = 256;
        int x = (y + n - (k % n)) % n;
        output += static_cast<char>(x);
    }
    return output;
}

std::string Trithemius_cipher::encrypt_raw_bytes_kw(const std::string& message)
{
    std::string output;
    for (int i = 0; i < message.size(); ++i) {
        int x = message[i];
        int k = m_lang.alphabet.find(m_key.keyword[i % m_key.keyword.size()]);
        int y = (x + k) % 256;
        output += static_cast<char>(y);
    }
    return output;
}

std::string Trithemius_cipher::decrypt_raw_bytes_kw(const std::string& message)
{
    std::string output;
    for (int i = 0; i < message.size(); i++) {
        int y = message[i];
        int k = m_lang.alphabet.find(m_key.keyword[i % m_key.keyword.size()]);
        int n = 256;
        int x = (y + n - (k % n)) % n;
        output += static_cast<char>(x);
    }
    return output;
}

// =============================================================================
//                                Breaking cipher
// =============================================================================

std::unordered_map<std::u16string, std::u16string>
Trithemius_cipher::break_cipher_freq(
        const std::u16string& message, const language& lang,
        const std::unordered_map<std::u16string, double>& common_lang_freq)
{
    return std::unordered_map<std::u16string, std::u16string>();
}

std::unordered_map<std::u16string, std::u16string>
Trithemius_cipher::break_cipher_msg_pair(
        const std::u16string& encrypted, const std::u16string& decrypted)
{
    return std::unordered_map<std::u16string, std::u16string>();
}

std::unordered_map<std::u16string, std::u16string>
Trithemius_cipher::break_cipher_v2_msg_pair(
        const std::u16string& encrypted, const std::u16string& decrypted)
{
    return std::unordered_map<std::u16string, std::u16string>();
}

}  // namespace petliukh::cryptography
