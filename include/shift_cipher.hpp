#pragma once
#include "cipher_base.hpp"

namespace petliukh::cryptography {

class Shift_cipher : public Cipher {
public:
    Shift_cipher();
    virtual std::u16string encrypt(const std::u16string& message) override;
    virtual std::u16string decrypt(const std::u16string& message) override;
    virtual std::string encrypt_raw_bytes(const std::string& bytes) override;
    virtual std::string decrypt_raw_bytes(const std::string& bytes) override;
    virtual void set_key(const std::u16string& key) override;
    void set_key(int key);
    virtual void set_lang(const std::u16string& lang) override;
    virtual void set_lang(const Language& lang) override;
    int get_key() const;
    std::unordered_map<int, std::u16string>
    brute_force(const std::u16string& message);

private:
    std::u16string encrypt_(const std::u16string& message, int key);
    std::u16string decrypt_(const std::u16string& message, int key);
    std::string encrypt_raw_bytes_(const std::string& bytes, int key);
    std::string decrypt_raw_bytes_(const std::string& bytes, int key);

    int m_key;
    Language m_lang;
};

}  // namespace petliukh::cryptography
