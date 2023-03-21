#pragma once
#include "cipher_base.hpp"

#include <Eigen/Dense>
#include <sstream>

namespace petliukh::cryptography {

namespace egn = Eigen;

class tritemius_cipher : public cipher {
public:
    enum class key_type { v2, v3, word };

    struct key {
        egn::Vector2i key_v2;
        egn::Vector3i key_v3;
        std::u16string keyword;
        key_type type;
    };

    tritemius_cipher();

    virtual std::u16string encrypt(const std::u16string& message) override;
    virtual std::u16string decrypt(const std::u16string& message) override;

    virtual std::string encrypt_raw_bytes(const std::string& bytes) override;
    virtual std::string decrypt_raw_bytes(const std::string& bytes) override;

    virtual void set_key(const std::u16string& key) override;
    key get_key() const;

    virtual void set_lang(const std::u16string& lang) override;
    virtual void set_lang(const language& lang) override;

private:
    bool validate_keyword(const std::u16string& keyword);

    std::u16string encrypt_v2(const std::u16string& message);
    std::u16string decrypt_v2(const std::u16string& message);

    std::u16string encrypt_v3(const std::u16string& message);
    std::u16string decrypt_v3(const std::u16string& message);

    std::u16string encrypt_word(const std::u16string& message);
    std::u16string decrypt_word(const std::u16string& message);

    key m_key;
    language m_lang;
};

}  // namespace petliukh::cryptography
