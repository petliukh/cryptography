#include "trithemius_cipher.hpp"

#include "string_utils.hpp"

#include <sstream>

namespace petliukh::cryptography {

Trithemius_cipher::Trithemius_cipher() : m_lang(Cipher::langs.at(u"EN"))
{
}

std::string Trithemius_cipher::Key::to_string() const
{
    switch (type) {
    case Key_type::vec: {
        std::stringstream ss;
        ss << vec;
        return ss.str();
    }
    case Key_type::word: {
        return utf16_to_utf8(keyword);
    }
    }
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
        int k = 0;
        switch (m_key.type) {
        case Key_type::vec:
            for (int j = m_key.vec.size() - 1; j >= 0; j--) {
                k += std::pow(i, j) * m_key.vec(j);
            }
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
        int k = 0;
        switch (m_key.type) {
        case Key_type::vec:
            for (int j = m_key.vec.size() - 1; j >= 0; j--) {
                k += std::pow(i, j) * m_key.vec(j);
            }
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
        int k = 0;
        switch (m_key.type) {
        case Key_type::vec:
            for (int j = m_key.vec.size() - 1; j >= 0; j--) {
                k += std::pow(i, j) * m_key.vec(j);
            }
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
        int k = 0;
        switch (m_key.type) {
        case Key_type::vec:
            for (int j = m_key.vec.size() - 1; j >= 0; j--) {
                k += std::pow(i, j) * m_key.vec(j);
            }
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
    auto key_parts = str_split(utf16_to_utf8(key), ',');
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

    m_key.type = Key_type::vec;
    m_key.vec = egn::VectorXi::Map(key_parts_num.data(), key_parts_num.size());
}

void Trithemius_cipher::set_key(const Trithemius_cipher::Key& key)
{
    m_key = key;
}

Trithemius_cipher::Key Trithemius_cipher::get_key() const
{
    return m_key;
}

void Trithemius_cipher::set_lang(const std::u16string& lang)
{
    m_lang = Cipher::langs.at(lang);
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

Trithemius_cipher::Key Trithemius_cipher::break_cipher_with_msg_pair(
        const std::u16string& enc, const std::u16string& dec) const
{
    if (enc.size() != dec.size()) {
        throw std::invalid_argument(
                "Encrypted and decrypted messages must be "
                "of the same length");
    }
    int vec_size = m_key.vec.size();
    egn::MatrixXd mtx(vec_size, vec_size);
    egn::VectorXd bv(vec_size);
    egn::ArrayXd xv;
    xv.resize(vec_size);
    int n = m_lang.alphabet.size();

    for (int i = 0; i < vec_size; i++) {
        int x = m_lang.alphabet.find(enc[i]);
        int y = m_lang.alphabet.find(dec[i]);
        int k = (x - y + n) % n;

        for (int j = vec_size - 1; j >= 0; j--) {
            mtx(i, j) = std::pow(i, j);
        }

        bv[i] = k;
    }
    xv = mtx.fullPivLu().solve(bv).array().round();
    Key key;
    key.type = Key_type::vec;
    key.vec = xv.matrix().cast<int>();

    return key;
}

std::map<std::u16string, std::u16string>
Trithemius_cipher::break_cipher_with_freqs(
        std::map<char16_t, double> lang_freqs, const std::u16string& enc) const
{
    std::map<char16_t, double> freqs = count_freqs(enc, m_lang);
    if (freqs.size() != lang_freqs.size()) {
        throw std::invalid_argument(
                "The message is not large enough to use freq analysis.");
    }
    std::u16string init_msg_guess;

    return {};
}

}  // namespace petliukh::cryptography
