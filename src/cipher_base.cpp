#include "cipher_base.hpp"

namespace petliukh::cryptography {

const std::u16string Cipher::special_chars = u" ,.?!:;()[]{}-_=+*/\\\"\'\n";
const std::unordered_map<std::u16string, Language> Cipher::langs = {
    { u"EN",
      Language{ u"EN", u"English",
                u"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                        + Cipher::special_chars } },
    { u"UKR",
      Language{ u"UKR", u"Ukrainian",
                u"абвгґдеєжзиіїйклмнопрстуфхцчшщьюяАБВГҐДЕЄЖЗИІЇЙКЛМНОП"
                u"РСТУФХЦЧШЩЬЮЯ"
                        + Cipher::special_chars } },
};

std::unordered_map<char16_t, int>
count_chars(const std::u16string& message, const Language& lang)
{
    std::unordered_map<char16_t, int> freqs;
    freqs.reserve(lang.alphabet.size());
    for (char16_t c : message) {
        if (lang.alphabet.find(c) != std::u16string::npos) {
            freqs[c]++;
        }
    }
    return freqs;
}

bool validate_msg(const std::u16string& msg, const std::u16string& lang)
{
    Language lang_ = Cipher::langs.at(lang);
    for (char16_t c : msg) {
        if (lang_.alphabet.find(c) == std::u16string::npos) {
            return false;
        }
    }
    return true;
}

bool validate_msg(const std::u16string& msg, const Language& lang)
{
    for (char16_t c : msg) {
        if (lang.alphabet.find(c) == std::u16string::npos) {
            return false;
        }
    }
    return true;
}

}  // namespace petliukh::cryptography
