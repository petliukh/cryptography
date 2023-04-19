#pragma once
#include "cipher_base.hpp"

#include <Eigen/Dense>
#include <map>
#include <string>

namespace petliukh::cryptography {

namespace egn = Eigen;

class Trithemius_cipher : public Cipher {
public:
    enum class Key_type { vec, word };

    struct Key {
        egn::VectorXi vec;
        std::u16string keyword;
        Key_type type;

        std::string to_string() const;
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
    Key break_cipher_with_msg_pair(
            const std::u16string& enc, const std::u16string& dec) const;
    std::map<std::u16string, std::u16string> break_cipher_with_freqs(
            std::map<char16_t, double> lang_freqs, const std::u16string& enc,
            int max_tries = 100) const;

private:
    bool validate_keyword(const std::u16string& keyword);
    std::u16string break_try(
            const std::u16string& enc,
            const std::vector<std::pair<char16_t, double>>& lang_freqs_vec,
            const std::vector<std::pair<char16_t, double>>& msg_freqs_vec)
            const;

    Key m_key;
    Language m_lang;
};

}  // namespace petliukh::cryptography
