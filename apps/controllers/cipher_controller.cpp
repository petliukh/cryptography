#include "cipher_controller.hpp"

namespace petliukh::controllers {

cipher_controller::cipher_controller() : m_lang("EN") {
    m_ciphers = {
        std::make_unique<cr::Shift_cipher>(),
        std::make_unique<cr::Trithemius_cipher>(),
    };
}

// ===========================================================================
//                             Getters
// ===========================================================================

std::string cipher_controller::get_key() const {
    return m_key;
}

std::string cipher_controller::get_lang() const {
    return m_lang;
}

std::string cipher_controller::get_filename() const {
    return m_filename;
}

std::string cipher_controller::get_content(int index) const {
    return m_content_arr[index];
}

int cipher_controller::get_curr_state() const {
    return m_curr_state;
}

// ===========================================================================
//                             Getters
// ===========================================================================

void cipher_controller::set_cipher_index(int idx) {
    m_curr_cipher = idx;
}

void cipher_controller::set_key(const std::string& key) {
    m_key = key;
    std::u16string u16key = cr::utf8_to_utf16(key);
    m_ciphers[m_curr_cipher]->set_key(u16key);
}

void cipher_controller::set_lang(const std::string& lang) {
    m_lang = lang;
    std::u16string u16lang = cr::utf8_to_utf16(lang);
    m_ciphers[m_curr_cipher]->set_lang(u16lang);
}

void cipher_controller::set_filename(const std::string& filename) {
    m_filename = filename;
}

void cipher_controller::set_content(int index, const std::string& content) {
    m_content_arr[index] = content;
}

void cipher_controller::set_curr_state(int index) {
    m_curr_state = index;
}

// ===========================================================================
//                             File
// ===========================================================================

std::string cipher_controller::read_file() {
    std::ifstream file(m_filename, std::ios::binary);
    std::string content(
            (std::istreambuf_iterator<char>(file)),
            (std::istreambuf_iterator<char>()));
    m_content_arr[m_curr_state] = content;
    return content;
}

void cipher_controller::save_file(int content_index) {
    std::ofstream file(m_filename, std::ios::trunc | std::ios::binary);
    file << m_content_arr[content_index];
}

void cipher_controller::save_file(const std::string& content) {
    std::ofstream file(m_filename, std::ios::trunc | std::ios::binary);
    file << content;
}

void cipher_controller::reset() {
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

std::string cipher_controller::encrypt(const std::string& message) {
    std::u16string u16message = cr::utf8_to_utf16(message);
    std::u16string res = m_ciphers[m_curr_cipher]->encrypt(u16message);
    return cr::utf16_to_utf8(res);
}

std::string cipher_controller::decrypt(const std::string& message) {
    std::u16string u16message = cr::utf8_to_utf16(message);
    std::u16string res = m_ciphers[m_curr_cipher]->decrypt(u16message);
    return cr::utf16_to_utf8(res);
}

std::string cipher_controller::encrypt_raw_bytes(const std::string& bytes) {
    return m_ciphers[m_curr_cipher]->encrypt_raw_bytes(bytes);
}

std::string cipher_controller::decrypt_raw_bytes(const std::string& bytes) {
    return m_ciphers[m_curr_cipher]->decrypt_raw_bytes(bytes);
}

std::unordered_map<char16_t, int>
cipher_controller::calc_freqs(std::string content) {
    cr::language lang = cr::languages.at(cr::utf8_to_utf16(m_lang));
    auto freqs = cr::get_message_freqs(cr::utf8_to_utf16(content), lang);
    return freqs;
}

std::unordered_map<int, std::string>
cipher_controller::brute_force(const std::string& message) {
    cr::Shift_cipher* sc = static_cast<cr::Shift_cipher*>(m_ciphers[0].get());
    auto res = sc->brute_force(cr::utf8_to_utf16(message));
    std::unordered_map<int, std::string> res_utf8;
    for (auto& [key, value] : res) {
        res_utf8[key] = cr::utf16_to_utf8(value);
    }
    return res_utf8;
}

}  // namespace petliukh::controllers
