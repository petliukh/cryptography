#include "knapsack_cipher.hpp"

#include "crypto_utils.hpp"
#include "numeric_utils.hpp"
#include "string_utils.hpp"

#include <algorithm>
#include <numeric>
#include <stdexcept>

#include <iostream>
#include <bitset>

namespace petliukh::cryptography {

// ============================================================================
//                         Constructors
// ============================================================================

Knapsack_cipher::Knapsack_cipher()
{
}

Knapsack_cipher::~Knapsack_cipher()
{
}

// ============================================================================
//                         Public interface
// ============================================================================

std::u16string Knapsack_cipher::encrypt(const std::u16string& message)
{
    std::vector<int16_t> msg(message.begin(), message.end());
    std::vector<int64_t> ciphertext = encrypt_with_public_key(msg);

    return utf8_to_utf16(vec_to_string(ciphertext));
}

std::u16string Knapsack_cipher::decrypt(const std::u16string& message)
{
    std::vector<int64_t> ints = str_to_vec_i64(utf16_to_utf8(message));
    std::vector<int16_t> res = decrypt_with_private_key(ints);
    return std::u16string(res.begin(), res.end());
}

std::string Knapsack_cipher::encrypt_raw_bytes(const std::string& bytes)
{
    std::vector<int16_t> msg(bytes.begin(), bytes.end());
    std::vector<int64_t> ciphertext = encrypt_with_public_key(msg);
    return vec_to_string(ciphertext);
}

std::string Knapsack_cipher::decrypt_raw_bytes(const std::string& bytes)
{
    std::vector<int64_t> ints = str_to_vec_i64(bytes);
    std::vector<int16_t> res = decrypt_with_private_key(ints);
    return std::string(res.begin(), res.end());
}

void Knapsack_cipher::generate_random_key()
{
    m_superinc_seq = generate_superincreasing_sequence(m_ks_size, m_max_growth);
    m_m = generate_rand_m(m_superinc_seq, m_max_growth);
    m_t = generate_rand_t(m_m);
    m_t_inv = mod_inverse(m_t, m_m);
    m_normal_ks_seq
            = generate_normal_knapsack_sequence(m_superinc_seq, m_m, m_t);
}

// ============================================================================
//                         Helper algorithms
// ============================================================================

std::vector<int64_t>
Knapsack_cipher::encrypt_with_public_key(const std::vector<int16_t>& msg)
{
    std::vector<int64_t> ciphertext;
    ciphertext.reserve(msg.size());

    for (int16_t block : msg) {
        int64_t sum = 0;
        for (int i = 0; i < m_ks_size; i++) {
            if (block & (1 << i)) {
                sum += m_normal_ks_seq[i];
            }
        }
        ciphertext.push_back(sum);

        std::cout << std::bitset<16>(block) << "\n";
    }
    std::cout << "\n";

    return ciphertext;
}

std::vector<int16_t>
Knapsack_cipher::decrypt_with_private_key(const std::vector<int64_t>& msg)
{
    std::vector<int16_t> plaintext;
    plaintext.reserve(msg.size());

    for (int64_t c : msg) {
        int64_t s = (c * m_t_inv) % m_m;
        int16_t p = solve_knapsack(m_superinc_seq, s);
        plaintext.push_back(p);

        std::cout << std::bitset<16>(p) << "\n";
    }
    std::cout << "\n";

    return plaintext;
}

// ============================================================================
//                         Getters & setters
// ============================================================================

void Knapsack_cipher::set_key(const std::u16string& key)
{
}

void Knapsack_cipher::set_lang(const std::u16string& lang)
{
}

void Knapsack_cipher::set_lang(const Language& lang)
{
}

void Knapsack_cipher::set_knapsack_size(int32_t size)
{
    m_ks_size = size;
}

void Knapsack_cipher::set_max_growth(int32_t n)
{
    m_max_growth = n;
}

// ============================================================================
//                         Helper functions
// ============================================================================

std::vector<int64_t>
generate_superincreasing_sequence(int32_t n, int32_t max_growth)
{
    std::vector<int64_t> supergrow_seq;
    supergrow_seq.reserve(n);
    int64_t prev_sum = 0;

    for (int64_t i = 0; i < n; i++) {
        supergrow_seq.push_back(prev_sum + rand_in_rng(1, max_growth));
        prev_sum += supergrow_seq.back();
    }
    return supergrow_seq;
}

std::vector<int64_t> generate_normal_knapsack_sequence(
        std::vector<int64_t> supergrowing_seq, int64_t m, int64_t t)
{
    std::vector<int64_t> normal_knapsack_seq;
    normal_knapsack_seq.reserve(supergrowing_seq.size());

    for (int64_t b : supergrowing_seq) {
        normal_knapsack_seq.push_back((b * t) % m);
    }
    return normal_knapsack_seq;
}

int64_t generate_rand_m(
        const std::vector<int64_t>& supergrowing_seq, int32_t max_growth)
{
    int64_t sum = std::accumulate(
            supergrowing_seq.begin(), supergrowing_seq.end(), 0);
    return sum + rand_in_rng(max_growth);
}

int64_t generate_rand_t(int64_t m)
{
    if (m % 2)
        m--;

    for (int64_t t = m - 1; t > 2; t -= 2) {
        if (std::gcd(m, t) == 1)
            return t;
    }
    return 2;
}

int16_t solve_knapsack(const std::vector<int64_t>& ks_seq, int64_t s)
{
    int n = ks_seq.size() - 1;
    int16_t bits;
    for (int i = n; i >= 0 && s > 0; i--) {
        if (s > ks_seq[i]) {
            s -= ks_seq[i];
            bits |= (1 << i);
        }
    }
    return bits;
}

}  // namespace petliukh::cryptography
