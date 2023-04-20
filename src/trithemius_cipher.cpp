#include "trithemius_cipher.hpp"

#include "map_utils.hpp"
#include "string_utils.hpp"
#include "crypto_utils.hpp"

#include <algorithm>
#include <sstream>

namespace petliukh::cryptography {

Trithemius_cipher::Trithemius_cipher()
    : m_key(Key{ egn::VectorXi::Zero(2), u"", Key_type::vec }),
      m_lang(Cipher::langs.at(u"EN"))
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
    return "";
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

std::u16string Trithemius_cipher::break_try(
        const std::u16string& enc,
        const std::vector<std::pair<char16_t, double>>& lang_freqs_vec,
        const std::vector<std::pair<char16_t, double>>& msg_freqs_vec) const
{
    std::u16string msg_guess;
    msg_guess.reserve(enc.size());
    for (char16_t chr : enc) {
        auto it = std::find_if(
                msg_freqs_vec.begin(), msg_freqs_vec.end(),
                [&](auto& e) { return e.first == chr; });
        int idx = std::distance(it, msg_freqs_vec.begin());
        msg_guess += lang_freqs_vec[idx % lang_freqs_vec.size()].first;
    }
    return msg_guess;
}

std::map<std::u16string, std::u16string>
Trithemius_cipher::break_cipher_with_freqs(
        std::map<char16_t, double> lang_freqs, const std::u16string& enc,
        int max_tries) const
{
    std::map<std::u16string, std::u16string> tries;
    std::map<char16_t, double> msg_freqs = count_freqs(enc, m_lang);

    std::vector<std::pair<char16_t, double>> lang_freqs_vec
            = vec_from_map(lang_freqs);
    std::vector<std::pair<char16_t, double>> msg_freqs_vec
            = vec_from_map(msg_freqs);

    auto sort_by = [](auto& left, auto& right) {
        return left.second < right.second;
    };

    std::sort(lang_freqs_vec.begin(), lang_freqs_vec.end(), sort_by);
    std::sort(msg_freqs_vec.begin(), msg_freqs_vec.end(), sort_by);

    for (int i = 0; i < max_tries; i++) {
        std::u16string msg_guess
                = break_try(enc, lang_freqs_vec, msg_freqs_vec);
        Key key_try = break_cipher_with_msg_pair(enc, msg_guess);
        std::u16string key_u16str = utf8_to_utf16(key_try.to_string());
        tries[key_u16str] = msg_guess;

        if (!std::next_permutation(
                    msg_freqs_vec.begin(), msg_freqs_vec.end())) {
            return tries;
        }
    }

    return tries;
}

std::u16string Trithemius_cipher::generate_random_keyword(int size)
{
    std::u16string keyword;
    keyword.reserve(size);
    for (int i = 0; i < size; i++) {
        int rnd = rand(0, m_lang.alphabet.size());
        keyword += m_lang.alphabet[rnd];
    }
    return keyword;
}

}  // namespace petliukh::cryptography
