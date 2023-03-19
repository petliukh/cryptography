#include "cipher_controller.hpp"

namespace petliukh::controllers {

cipher_controller::cipher_controller() {
    m_ciphers = {
        std::make_unique<cr::shift_cipher>(),
        std::make_unique<cr::tritemius_cipher>(),
    };
}

// ===========================================================================
//                             Misc
// ===========================================================================

void cipher_controller::set_cipher(int idx) {
    m_curr_idx = idx;
}

void cipher_controller::set_key(const std::string& key) {
    std::u16string u16key = cr::utf8_to_utf16(key);
    m_ciphers[m_curr_idx]->set_key(u16key);
}

void cipher_controller::set_lang(const std::string& lang) {
    std::u16string u16lang = cr::utf8_to_utf16(lang);
    m_ciphers[m_curr_idx]->set_lang(u16lang);
}

void cipher_controller::set_filename(const std::string& filename) {
    m_filename = filename;
}

void cipher_controller::set_filecontent(const std::string& content) {
    m_filecontent = content;
}

void cipher_controller::read_file() {
    std::ifstream file(m_filename);
    std::string content(
            (std::istreambuf_iterator<char>(file)),
            (std::istreambuf_iterator<char>()));
    m_filecontent = content;
}

std::string cipher_controller::get_filecontent() const {
    return m_filecontent;
}

void cipher_controller::save_file() {
    std::ofstream file(m_filename, std::ios::trunc | std::ios::binary);
    file << m_filecontent;
}

// ===========================================================================
//                             Cipher methods
// ===========================================================================

std::string cipher_controller::encrypt(const std::string& message) {
    std::u16string u16message = cr::utf8_to_utf16(message);
    std::u16string res = m_ciphers[m_curr_idx]->encrypt(u16message);
    return cr::utf16_to_utf8(res);
}

std::string cipher_controller::decrypt(const std::string& message) {
    std::u16string u16message = cr::utf8_to_utf16(message);
    std::u16string res = m_ciphers[m_curr_idx]->decrypt(u16message);
    return cr::utf16_to_utf8(res);
}

std::string cipher_controller::encrypt_raw_bytes(const std::string& bytes) {
    return m_ciphers[m_curr_idx]->encrypt_raw_bytes(bytes);
}

std::string cipher_controller::decrypt_raw_bytes(const std::string& bytes) {
    return m_ciphers[m_curr_idx]->decrypt_raw_bytes(bytes);
}

}  // namespace petliukh::controllers
