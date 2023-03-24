#pragma once
#include "cipher_base.hpp"

#include <Eigen/Dense>
#include <sstream>

namespace petliukh::cryptography {

namespace egn = Eigen;

class Trithemius_cipher : public Cipher {
public:
    enum class key_type { v2, v3, word };

    struct key {
        egn::Vector2i key_v2;
        egn::Vector3i key_v3;
        std::u16string keyword;
        key_type type;
    };

    Trithemius_cipher();

    virtual std::u16string encrypt(const std::u16string& message) override;
    virtual std::u16string decrypt(const std::u16string& message) override;

    virtual std::string encrypt_raw_bytes(const std::string& bytes) override;
    virtual std::string decrypt_raw_bytes(const std::string& bytes) override;

    virtual void set_key(const std::u16string& key) override;
    key get_key() const;

    virtual void set_lang(const std::u16string& lang) override;
    virtual void set_lang(const language& lang) override;

    std::unordered_map<std::u16string, std::u16string> break_cipher_freq(
            const std::u16string& message,
            const language& lang,
            const std::unordered_map<std::u16string, double>& common_lang_freq);

    std::unordered_map<std::u16string, std::u16string>
    break_cipher_msg_pair(const std::u16string& encrypted, const std::u16string& decrypted);

private:
    bool validate_keyword(const std::u16string& keyword);

    std::u16string encrypt_v2(const std::u16string& message);
    std::u16string decrypt_v2(const std::u16string& message);

    std::u16string encrypt_v3(const std::u16string& message);
    std::u16string decrypt_v3(const std::u16string& message);

    std::u16string encrypt_kw(const std::u16string& message);
    std::u16string decrypt_kw(const std::u16string& message);

    std::string encrypt_raw_bytes_v2(const std::string& bytes);
    std::string decrypt_raw_bytes_v2(const std::string& bytes);

    std::string encrypt_raw_bytes_v3(const std::string& bytes);
    std::string decrypt_raw_bytes_v3(const std::string& bytes);

    std::string encrypt_raw_bytes_kw(const std::string& bytes);
    std::string decrypt_raw_bytes_kw(const std::string& bytes);

    std::unordered_map<std::u16string, std::u16string> break_cipher_v2_freq(
            const std::u16string& message,
            const language& lang,
            const std::unordered_map<std::u16string, double>& common_freq);

    std::unordered_map<std::u16string, std::u16string> break_cipher_v3_freq(
            const std::u16string& msg,
            const language lang,
            const std::unordered_map<std::u16string, double>& common_freq);

    std::unordered_map<std::u16string, std::u16string> break_cipher_kw_freq(
            const std::u16string& msg,
            const language lang,
            const std::unordered_map<std::u16string, double>& common_freq);

    std::unordered_map<std::u16string, std::u16string> break_cipher_v2_msg_pair(
            const std::u16string& enc,
            const std::u16string& dec);

    std::unordered_map<std::u16string, std::u16string> break_cipher_v3_msg_pair(
            const std::u16string& enc,
            const std::u16string& dec);

    std::unordered_map<std::u16string, std::u16string> break_cipher_kw_msg_pair(
            const std::u16string& enc,
            const std::u16string& dec);

    key m_key;
    language m_lang;
};

}  // namespace petliukh::cryptography
