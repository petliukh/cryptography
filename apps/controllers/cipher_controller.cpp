#include "cipher_controller.hpp"

#include "shift_cipher.hpp"
#include "string_utils.hpp"
#include "trithemius_cipher.hpp"

#include <fstream>

namespace petliukh::controllers {
namespace su = petliukh::string_utils;

Cipher_controller::Cipher_controller() : m_lang("EN")
{
    m_ciphers = {
        std::make_unique<cr::Shift_cipher>(),
        std::make_unique<cr::Trithemius_cipher>(),
    };
}

// ===========================================================================
//                             Getters
// ===========================================================================

std::string Cipher_controller::get_key() const
{
    return m_key;
}

std::string Cipher_controller::get_lang() const
{
    return m_lang;
}

std::string Cipher_controller::get_filename() const
{
    return m_filename;
}

std::string Cipher_controller::get_content(int index) const
{
    return m_content_arr[index];
}

int Cipher_controller::get_curr_state() const
{
    return m_curr_state;
}

// ===========================================================================
//                             Getters
// ===========================================================================

void Cipher_controller::set_cipher_index(int idx)
{
    m_curr_cipher = idx;
}

void Cipher_controller::set_key(const std::string& key)
{
    m_key = key;
    std::u16string u16key = su::utf8_to_utf16(key);
    m_ciphers[m_curr_cipher]->set_key(u16key);
}

void Cipher_controller::set_lang(const std::string& lang)
{
    m_lang = lang;
    std::u16string u16lang = su::utf8_to_utf16(lang);
    m_ciphers[m_curr_cipher]->set_lang(u16lang);
}

void Cipher_controller::set_filename(const std::string& filename)
{
    m_filename = filename;
}

void Cipher_controller::set_content(int index, const std::string& content)
{
    m_content_arr[index] = content;
}

void Cipher_controller::set_curr_state(int index)
{
    m_curr_state = index;
}

// ===========================================================================
//                             File
// ===========================================================================

std::string Cipher_controller::read_file()
{
    std::ifstream file(m_filename, std::ios::binary);
    std::string content(
            (std::istreambuf_iterator<char>(file)),
            (std::istreambuf_iterator<char>()));
    m_content_arr[m_curr_state] = content;
    return content;
}

void Cipher_controller::save_file(int content_index)
{
    std::ofstream file(m_filename, std::ios::trunc | std::ios::binary);
    file << m_content_arr[content_index];
}

void Cipher_controller::save_file(const std::string& content)
{
    std::ofstream file(m_filename, std::ios::trunc | std::ios::binary);
    file << content;
}

void Cipher_controller::reset()
{
    m_filename = "";
    m_key = "";
    m_lang = "EN";
    m_curr_cipher = 0;
    m_curr_state = 0;
    m_content_arr = {};
}

// ===========================================================================
//                             Cipher methods
// ===========================================================================

std::string Cipher_controller::encrypt(const std::string& message)
{
    std::u16string u16message = su::utf8_to_utf16(message);
    std::u16string res = m_ciphers[m_curr_cipher]->encrypt(u16message);
    return su::utf16_to_utf8(res);
}

std::string Cipher_controller::decrypt(const std::string& message)
{
    std::u16string u16message = su::utf8_to_utf16(message);
    std::u16string res = m_ciphers[m_curr_cipher]->decrypt(u16message);
    return su::utf16_to_utf8(res);
}

std::string Cipher_controller::encrypt_raw_bytes(const std::string& bytes)
{
    return m_ciphers[m_curr_cipher]->encrypt_raw_bytes(bytes);
}

std::string Cipher_controller::decrypt_raw_bytes(const std::string& bytes)
{
    return m_ciphers[m_curr_cipher]->decrypt_raw_bytes(bytes);
}

std::map<char16_t, int>
Cipher_controller::calc_freqs(std::string content)
{
    cr::Language lang = cr::Cipher::langs.at(su::utf8_to_utf16(m_lang));
    auto freqs = cr::count_chars(su::utf8_to_utf16(content), lang);
    return freqs;
}

std::map<int, std::string>
Cipher_controller::brute_force(const std::string& message)
{
    cr::Shift_cipher* sc = static_cast<cr::Shift_cipher*>(m_ciphers[0].get());
    auto res = sc->brute_force(su::utf8_to_utf16(message));
    std::map<int, std::string> res_utf8;
    for (auto& [key, value] : res) {
        res_utf8[key] = su::utf16_to_utf8(value);
    }
    return res_utf8;
}

// ============================================================================
//                            Trithemius cipher
// ============================================================================

std::string
Cipher_controller::break_trithemius_cipher_key(std::string enc, std::string dec)
{
    using T_key = cr::Trithemius_cipher::Key;
    using Key_type = cr::Trithemius_cipher::Key_type;

    cr::Trithemius_cipher* tc
            = (cr::Trithemius_cipher*) m_ciphers[m_curr_cipher].get();

    std::u16string u16enc = su::utf8_to_utf16(enc);
    std::u16string u16dec = su::utf8_to_utf16(dec);
    T_key key = tc->break_cipher_with_msg_pair(u16enc, u16dec);
    std::stringstream ss;

    switch (key.type) {
    case Key_type::vec:
        ss << key.vec;
        break;
    default:
        throw std::invalid_argument("Not implemented");
    }

    return ss.str();
}

}  // namespace petliukh::controllers
