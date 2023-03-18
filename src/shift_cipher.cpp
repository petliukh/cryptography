#include "shift_cipher.hpp"

#include <fstream>
#include <stdexcept>

using std::ifstream, std::ofstream, std::ios;
using std::string, std::u16string;
using std::unordered_map;
using std::vector;

namespace petliukh::cryptography {

const u16string shift_cipher::special_chars = u" ,.?!:;()[]{}-_=+*/\\\"\'\n";
const unordered_map<u16string, language> shift_cipher::languages = {
    { u"EN",
      { u"EN", u"English",
        u"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" } },
    { u"UKR",
      { u"UKR", u"Ukrainian",
        u"абвгґдеєжзиіїйклмнопрстуфхцчшщьюяАБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮ"
        u"Я" } }
};

shift_cipher::shift_cipher()
    : m_lang(languages.at(u"EN")), m_max_msg_length(1000) {
}

shift_cipher::shift_cipher(language lang, int max_text_length)
    : m_lang(lang), m_max_msg_length(max_text_length) {
}

shift_cipher::shift_cipher(u16string lang, int max_data_size)
    : m_lang(languages.at(lang)), m_max_msg_length(max_data_size) {
}

u16string
shift_cipher::encrypt_text(const u16string& plaintext, int key) const {
    validate_key(key);
    validate_message(plaintext);
    u16string ciphertext;
    for (char16_t c : plaintext) {
        int pos = m_lang.alphabet.find(c);
        if (pos != u16string::npos) {
            pos = (pos + key) % m_lang.alphabet.size();
            ciphertext += m_lang.alphabet[pos];
        } else {
            ciphertext += c;
        }
    }
    return ciphertext;
}

u16string
shift_cipher::decrypt_text(const u16string& ciphertext, int key) const {
    return encrypt_text(ciphertext, m_lang.alphabet.size() - key);
}

vector<message> shift_cipher::brute_force(const u16string& ciphertext) const {
    vector<message> messages;
    messages.reserve(m_lang.alphabet.size());
    for (int key = 0; key < m_lang.alphabet.size(); key++) {
        messages.push_back({ decrypt_text(ciphertext, key), key });
    }
    return messages;
}

void shift_cipher::encrypt_file(
        const string& input_file, int key, const string& output_file) const {
    string output_file_name
            = output_file.empty() ? input_file + ".tmp" : output_file;
    ifstream ifs(input_file, ios::binary);
    ofstream ofs(output_file_name, ios::binary);
    char c;

    while (ifs.get(c)) {
        c = (c + key) % 256;
        ofs.put(c);
    }

    ifs.close();
    ofs.close();

    if (output_file.empty())
        rename(output_file_name.c_str(), input_file.c_str());
}

void shift_cipher::decrypt_file(
        const string& input_file, int key, const string& output_file) const {
    encrypt_file(input_file, 256 - key, output_file);
}

void shift_cipher::validate_key(int key) const {
    if (key < 0 || key > m_lang.alphabet.size())
        throw std::invalid_argument(
                "Invalid key: key is out of range of the "
                "alphabet");
}

void shift_cipher::validate_message(const u16string& message) const {
    int i = 0;
    for (char16_t c : message) {
        if (m_lang.alphabet.find(c) == u16string::npos
            && special_chars.find(c) == u16string::npos) {
            throw std::invalid_argument(
                    "Can't encrypt the message as it contains "
                    "characters that are not in the alphabet");
        }
        i++;
    }
}

unordered_map<char16_t, int>
shift_cipher::get_frequency(const u16string& text) const {
    unordered_map<char16_t, int> char_frequency;
    for (char16_t c : text) {
        if (char_frequency.find(c) == char_frequency.end()) {
            char_frequency[c] = 1;
        } else {
            char_frequency[c]++;
        }
    }
    return char_frequency;
}

}  // namespace petliukh::cryptography
