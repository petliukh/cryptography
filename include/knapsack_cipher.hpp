#pragma once
#include "cipher_base.hpp"

#include <BigInt.hpp>
#include <vector>

namespace petliukh::cryptography {

class Knapsack_cipher : public Cipher {
public:
    constexpr static size_t text_keysize = 16;
    constexpr static size_t bin_keysize = 8;

    struct Key {
        std::vector<BigInt> superinc_seq;
        std::vector<BigInt> knapsack_seq;
        BigInt m;
        BigInt t;
        BigInt t_inv;
        char separator = ' ';

        std::string to_string() const;
    };

    Knapsack_cipher();
    virtual ~Knapsack_cipher();
    virtual std::u16string encrypt(const std::u16string& message) override;
    virtual std::u16string decrypt(const std::u16string& message) override;
    virtual std::string encrypt_raw_bytes(const std::string& bytes) override;
    virtual std::string decrypt_raw_bytes(const std::string& bytes) override;
    virtual void set_key(const std::u16string& key) override;
    virtual void set_lang(const std::u16string& lang) override;
    virtual void set_lang(const Language& lang) override;

    void generate_rand_key(size_t inc_digits);
    void set_separator(char sep);
    const Key& get_key() const;

private:
    Key m_key;
};

std::vector<BigInt> generate_superincreasing_sequence(
        size_t size, size_t start_digits, size_t inc_digits);
BigInt generate_rand_modulus(
        const std::vector<BigInt>& superinc_seq, size_t inc_digits);
BigInt generate_rand_multiplier(const BigInt& m);
std::vector<BigInt> generate_knapsack_sequence(
        const std::vector<BigInt>& superinc_seq, const BigInt& m,
        const BigInt& t);
char16_t solve_knapsack(const std::vector<BigInt>& superinc_seq, BigInt s);

}  // namespace petliukh::cryptography
