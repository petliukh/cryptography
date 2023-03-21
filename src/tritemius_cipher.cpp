#include "tritemius_cipher.hpp"

namespace petliukh::cryptography {

tritemius_cipher::tritemius_cipher() : m_lang(languages.at(u"EN")) {
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

tritemius_cipher::key tritemius_cipher::get_key() const {
    return m_key;
}

void tritemius_cipher::set_lang(const std::u16string& lang) {
    m_lang = languages.at(lang);
}

void tritemius_cipher::set_lang(const language& lang) {
    m_lang = lang;
}

bool tritemius_cipher::validate_keyword(const std::u16string& keyword) {
    for (auto c : keyword) {
        if (m_lang.alphabet.find(c) == std::string::npos) {
            return false;
        }
    }
    return true;
}

std::u16string tritemius_cipher::encrypt_v2(const std::u16string& message) {
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

std::u16string tritemius_cipher::decrypt_v2(const std::u16string& message) {
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
    return std::u16string();
}

std::u16string tritemius_cipher::encrypt_v3(const std::u16string& message) {
    return std::u16string();
}

std::u16string tritemius_cipher::decrypt_v3(const std::u16string& message) {
    return std::u16string();
}

std::u16string tritemius_cipher::encrypt_word(const std::u16string& message) {
    return std::u16string();
}

std::u16string tritemius_cipher::decrypt_word(const std::u16string& message) {
    return std::u16string();
}

}  // namespace petliukh::cryptography
