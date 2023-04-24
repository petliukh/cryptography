#pragma once
#include "cipher_base.hpp"

#include <cstdint>
#include <vector>

namespace petliukh::cryptography {

class Knapsack_cipher : public Cipher {
public:
    Knapsack_cipher();
    virtual ~Knapsack_cipher();
    virtual std::u16string encrypt(const std::u16string& message) override;
    virtual std::u16string decrypt(const std::u16string& message) override;
    virtual std::string encrypt_raw_bytes(const std::string& bytes) override;
    virtual std::string decrypt_raw_bytes(const std::string& bytes) override;
    virtual void set_key(const std::u16string& key) override;
    virtual void set_lang(const std::u16string& lang) override;
    virtual void set_lang(const Language& lang) override;

    void generate_random_key();
    void set_max_growth(int32_t n);
    void set_knapsack_size(int32_t n);

private:
    std::vector<int64_t>
    encrypt_with_public_key(const std::vector<int16_t>& msg);
    std::vector<int16_t>
    decrypt_with_private_key(const std::vector<int64_t>& msg);

    std::vector<int64_t> m_superinc_seq;
    std::vector<int64_t> m_normal_ks_seq;
    int64_t m_m{};
    int64_t m_t{};
    int64_t m_t_inv{};
    int32_t m_ks_size{};
    int32_t m_max_growth = 10000;
};

std::vector<int64_t>
generate_superincreasing_sequence(int32_t size, int32_t max_growth);
std::vector<int64_t> generate_normal_knapsack_sequence(
        std::vector<int64_t> superinc_seq, int64_t m, int64_t t);
int64_t
generate_rand_m(const std::vector<int64_t>& superinc_seq, int32_t max_growth);
int64_t generate_rand_t(int64_t m);
int16_t solve_knapsack(const std::vector<int64_t>& ks_seq, int64_t s);

}  // namespace petliukh::cryptography
