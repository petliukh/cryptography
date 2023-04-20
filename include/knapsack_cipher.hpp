#pragma once
#include "cipher_base.hpp"
#include <vector>

namespace petliukh::cryptography {

class Knapsack_cipher : public Cipher {
public:
    virtual ~Knapsack_cipher() = default;
    virtual std::u16string encrypt(const std::u16string& message) override;
    virtual std::u16string decrypt(const std::u16string& message) override;
    virtual std::string encrypt_raw_bytes(const std::string& bytes) override;
    virtual std::string decrypt_raw_bytes(const std::string& bytes) override;
    virtual void set_key(const std::u16string& key) override;
    virtual void set_lang(const std::u16string& lang) override;
    virtual void set_lang(const Language& lang) override;
};

std::vector<size_t> generate_supergrowing_sequence(int n);

}
