#pragma once
#include <codecvt>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <locale>
#include <openssl/sha.h>
#include <stdexcept>
#include <string>
#include <map>
#include <unordered_map>
#include <vector>

namespace petliukh::cryptography {

struct Language {
    std::u16string code;
    std::u16string name;
    std::u16string alphabet;
};

class Cipher {
public:
    virtual ~Cipher() = default;

    virtual std::u16string encrypt(const std::u16string& message) = 0;

    virtual std::u16string decrypt(const std::u16string& message) = 0;

    virtual std::string encrypt_raw_bytes(const std::string& bytes) = 0;

    virtual std::string decrypt_raw_bytes(const std::string& bytes) = 0;

    virtual void set_key(const std::u16string& key) = 0;

    virtual void set_lang(const std::u16string& lang) = 0;

    virtual void set_lang(const Language& lang) = 0;
};

std::unordered_map<char16_t, int>
get_message_freqs(const std::u16string& message, const Language& lang);

bool validate_message(const std::u16string& message, const Language& lang);

std::string utf16_to_utf8(const std::u16string& utf16);

std::u16string utf8_to_utf16(const std::string& utf8);

std::string sha256(const std::string& str);

std::string sha256(const std::u16string& str);

std::vector<std::string> ssplit(const std::string& str, char delimiter);

const std::u16string special_chars = u" ,.?!:;()[]{}-_=+*/\\\"\'\n";

const std::unordered_map<std::u16string, Language> languages = {
    { u"EN",
      Language{ u"EN", u"English",
                u"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                        + special_chars } },
    { u"UKR",
      Language{ u"UKR", u"Ukrainian",
                u"абвгґдеєжзиіїйклмнопрстуфхцчшщьюяАБВГҐДЕЄЖЗИІЇЙКЛМНОП"
                u"РСТУФХЦЧШЩЬЮЯ"
                        + special_chars } },
};

}  // namespace petliukh::cryptography
