#pragma once
#include "cipher_base.hpp"

#include <Eigen/Dense>

namespace petliukh::cryptography {

namespace egn = Eigen;

class Trithemius_cipher : public Cipher {
public:
    enum class Key_type { v2, v3, word };

    struct Key {
        egn::Vector2i v2;
        egn::Vector3i v3;
        std::u16string keyword;
        Key_type type;
    };

    Trithemius_cipher();
    virtual std::u16string encrypt(const std::u16string& message) override;
    virtual std::u16string decrypt(const std::u16string& message) override;
    virtual std::string encrypt_raw_bytes(const std::string& bytes) override;
    virtual std::string decrypt_raw_bytes(const std::string& bytes) override;
    virtual void set_key(const std::u16string& key) override;
    void set_key(const Key& key);
    Key get_key() const;
    virtual void set_lang(const std::u16string& lang) override;
    virtual void set_lang(const Language& lang) override;
    Key break_cipher(const std::u16string& enc, const std::u16string& dec);

private:
    bool validate_keyword(const std::u16string& keyword);
    Key break_cipher_v2(const std::u16string& enc, const std::u16string& dec);
    Key break_cipher_v3(const std::u16string& enc, const std::u16string& dec);

    Key m_key;
    Language m_lang;
};

}  // namespace petliukh::cryptography
