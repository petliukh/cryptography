#include "trithemius_cipher.hpp"

namespace petliukh::cryptography {

Trithemius_cipher::Trithemius_cipher() : m_lang(languages.at(u"EN"))
{
}

std::u16string Trithemius_cipher::encrypt(const std::u16string& message)
{
    std::u16string output;
    for (int i = 0; i < message.size(); ++i) {
        int x = m_lang.alphabet.find(message[i]);
        if (x == std::string::npos) {
            output += message[i];
            continue;
        }
        int k;
        switch (m_key.type) {
        case Key_type::v2:
            k = m_key.v2.x() * i + m_key.v2.y();
            break;
        case Key_type::v3:
            k = m_key.v3.x() * i * i + m_key.v3.y() * i + m_key.v3.z();
            break;
        case Key_type::word:
            k = m_lang.alphabet.find(m_key.keyword[i % m_key.keyword.size()]);
            break;
        }
        int y = (x + k) % m_lang.alphabet.size();
        output += m_lang.alphabet[y];
    }
    return output;
}

std::u16string Trithemius_cipher::decrypt(const std::u16string& message)
{
    std::u16string output;
    for (int i = 0; i < message.size(); i++) {
        int y = m_lang.alphabet.find(message[i]);
        if (y == std::string::npos) {
            output += message[i];
            continue;
        }
        int k;
        switch (m_key.type) {
        case Key_type::v2:
            k = m_key.v2.x() * i + m_key.v2.y();
            break;
        case Key_type::v3:
            k = m_key.v3.x() * i * i + m_key.v3.y() * i + m_key.v3.z();
            break;
        case Key_type::word:
            k = m_lang.alphabet.find(m_key.keyword[i % m_key.keyword.size()]);
            break;
        }
        int n = m_lang.alphabet.size();
        int x = (y + n - (k % n)) % n;
        output += m_lang.alphabet[x];
    }
    return output;
}

std::string Trithemius_cipher::encrypt_raw_bytes(const std::string& bytes)
{
    std::string output;
    for (int i = 0; i < bytes.size(); ++i) {
        int x = bytes[i];
        int k;
        switch (m_key.type) {
        case Key_type::v2:
            k = m_key.v2.x() * i + m_key.v2.y();
            break;
        case Key_type::v3:
            k = m_key.v3.x() * i * i + m_key.v3.y() * i + m_key.v3.z();
            break;
        case Key_type::word:
            k = m_lang.alphabet.find(m_key.keyword[i % m_key.keyword.size()]);
            break;
        }
        int y = (x + k) % 256;
        output += static_cast<char>(y);
    }
    return output;
}

std::string Trithemius_cipher::decrypt_raw_bytes(const std::string& bytes)
{
    std::string output;
    for (int i = 0; i < bytes.size(); i++) {
        int y = bytes[i];
        int k;
        switch (m_key.type) {
        case Key_type::v2:
            k = m_key.v2.x() * i + m_key.v2.y();
            break;
        case Key_type::v3:
            k = m_key.v3.x() * i * i + m_key.v3.y() * i + m_key.v3.z();
            break;
        case Key_type::word:
            k = m_lang.alphabet.find(m_key.keyword[i % m_key.keyword.size()]);
            break;
        }
        int n = 256;
        int x = (y + n - (k % n)) % n;
        output += static_cast<char>(x);
    }
    return output;
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
            m_key.type = Key_type::word;
            m_key.keyword = keyword;
            return;
        }
    }

    if (key_parts_num.size() == 2) {
        m_key.type = Key_type::v2;
        m_key.v2 = egn::Vector2i(key_parts_num[0], key_parts_num[1]);
    } else if (key_parts_num.size() == 3) {
        m_key.type = Key_type::v3;
        m_key.v3 = egn::Vector3i(
                key_parts_num[0], key_parts_num[1], key_parts_num[2]);
    } else {
        throw std::invalid_argument("Invalid key");
    }
}

void Trithemius_cipher::set_key(const Trithemius_cipher::Key& key) {
    m_key = key;
}

Trithemius_cipher::Key Trithemius_cipher::get_key() const
{
    return m_key;
}

void Trithemius_cipher::set_lang(const std::u16string& lang)
{
    m_lang = languages.at(lang);
}

void Trithemius_cipher::set_lang(const Language& lang)
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

// =============================================================================
//                                Breaking cipher
// =============================================================================

Trithemius_cipher::Key Trithemius_cipher::break_cipher(
        const std::u16string& enc, const std::u16string& dec)
{
    switch (m_key.type) {
    case Key_type::v2:
        return break_cipher_v2(enc, dec);
    case Key_type::v3:
        return break_cipher_v3(enc, dec);
    default:
        throw std::invalid_argument(
                "Breaking for this type of key is not implemented.");
    }
}

Trithemius_cipher::Key Trithemius_cipher::break_cipher_v2(
        const std::u16string& enc, const std::u16string& dec)
{
    if (enc.size() != dec.size()) {
        throw std::invalid_argument(
                "Encrypted and decrypted messages must be "
                "of the same length");
    }
    egn::MatrixXd mtx(2, 2);
    egn::VectorXd bv(2);
    egn::Array2d xv;
    int n = m_lang.alphabet.size();

    for (int i = 0; i < 2; i++) {
        int x = m_lang.alphabet.find(enc[i]);
        int y = m_lang.alphabet.find(dec[i]);
        int k = (x - y + n) % n;
        mtx(i, 0) = i;
        mtx(i, 1) = 1;
        bv[i] = k;
    }
    xv = mtx.fullPivLu().solve(bv).array().round();
    Key key;
    key.type = Key_type::v2;
    key.v2 = xv.matrix().cast<int>();

    return key;
}

Trithemius_cipher::Key Trithemius_cipher::break_cipher_v3(
        const std::u16string& enc, const std::u16string& dec)
{
    if (enc.size() != dec.size()) {
        throw std::invalid_argument(
                "Encrypted and decrypted messages must be "
                "of the same length");
    }
    egn::MatrixXd mtx(3, 3);
    egn::VectorXd bv(3);
    egn::Array3d xv;
    int n = m_lang.alphabet.size();

    for (int i = 0; i < 3; i++) {
        int x = m_lang.alphabet.find(enc[i]);
        int y = m_lang.alphabet.find(dec[i]);
        int k = (x - y + n) % n;
        mtx(i, 0) = i * i;
        mtx(i, 1) = i;
        mtx(i, 2) = 1;
        bv[i] = k;
    }
    xv = mtx.fullPivLu().solve(bv).array().round();
    Key key;
    key.type = Key_type::v3;
    key.v3 = xv.matrix().cast<int>();

    return key;
}

}  // namespace petliukh::cryptography
