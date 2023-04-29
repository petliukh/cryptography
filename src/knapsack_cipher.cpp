#include "knapsack_cipher.hpp"

#include "numeric_utils.hpp"
#include "string_utils.hpp"

#include <numeric>
#include <sstream>
#include <bitset>

namespace petliukh::cryptography {

Knapsack_cipher::Knapsack_cipher()
{
}

Knapsack_cipher::~Knapsack_cipher()
{
}

std::string Knapsack_cipher::Key::to_string() const
{
    std::stringstream ss;
    ss << m << separator << t << separator;
    for (size_t i = 0; i < superinc_seq.size(); i++) {
        ss << superinc_seq[i];
        if (i != superinc_seq.size() - 1)
            ss << separator;
    }
    return ss.str();
}

std::u16string Knapsack_cipher::encrypt(const std::u16string& message)
{
    std::stringstream ss;

    for (size_t i = 0; i < message.size(); i++) {
        BigInt c = 0;

        for (size_t j = 0; j < text_keysize; j++) {
            if (message[i] & (1 << j)) {
                c += m_key.knapsack_seq[j];
            }
        }
        ss << c;

        if (i != message.size() - 1)
            ss << m_key.separator;
    }
    return utf8_to_utf16(ss.str());
}

std::u16string Knapsack_cipher::decrypt(const std::u16string& message)
{
    std::vector<std::string> ciphertext
            = str_split(utf16_to_utf8(message), m_key.separator);
    std::u16string decrypted_msg;

    for (const auto& c_str: ciphertext) {
        BigInt c = c_str;
        BigInt c_prime = (m_key.t_inv * c) % m_key.m;
        char16_t dec_chr = solve_knapsack(m_key.superinc_seq, c_prime);
        decrypted_msg += dec_chr;
    }

    return decrypted_msg;
}

std::string Knapsack_cipher::encrypt_raw_bytes(const std::string& bytes)
{
    std::u16string u16 = utf8_to_utf16(bytes);
    return utf16_to_utf8(encrypt(u16));
}

std::string Knapsack_cipher::decrypt_raw_bytes(const std::string& bytes)
{
    std::u16string u16 = utf8_to_utf16(bytes);
    return utf16_to_utf8(decrypt(u16));
}

void Knapsack_cipher::set_key(const std::u16string& key)
{
    std::vector<std::string> key_nums = str_split(utf16_to_utf8(key), m_key.separator);
    m_key.m = key_nums[0];
    m_key.t = key_nums[1];

    for (size_t i = 2; i < key_nums.size(); i++) {
        m_key.superinc_seq.emplace_back(key_nums[i]);
    }

    m_key.knapsack_seq = generate_knapsack_sequence(
            m_key.superinc_seq, m_key.m, m_key.t);
    m_key.t_inv = mod_inverse(m_key.t, m_key.m);
}

void Knapsack_cipher::set_lang(const std::u16string& lang)
{
}

void Knapsack_cipher::set_lang(const Language& lang)
{
}

void Knapsack_cipher::generate_rand_key(size_t inc_digits)
{
    m_key.superinc_seq = generate_superincreasing_sequence(
            text_keysize, inc_digits, inc_digits);
    m_key.m = generate_rand_modulus(m_key.superinc_seq, inc_digits);
    m_key.t = generate_rand_multiplier(m_key.m);
    m_key.t_inv = mod_inverse(m_key.t, m_key.m);
    m_key.knapsack_seq
            = generate_knapsack_sequence(m_key.superinc_seq, m_key.m, m_key.t);
}


void Knapsack_cipher::set_separator(char sep)
{
    m_key.separator = sep;
}

const Knapsack_cipher::Key& Knapsack_cipher::get_key() const
{
    return m_key;
}

std::vector<BigInt> generate_superincreasing_sequence(
        size_t size, size_t start_digits, size_t inc_digits)
{
    std::vector<BigInt> superinc_seq;
    superinc_seq.reserve(size);
    BigInt sum = big_random(start_digits);
    superinc_seq.push_back(sum);

    for (size_t i = 1; i < size; i++) {
        superinc_seq.push_back(sum + big_random(inc_digits));
        sum += superinc_seq.back();
    }

    return superinc_seq;
}

BigInt generate_rand_modulus(
        const std::vector<BigInt>& superinc_seq, size_t inc_digits)
{
    return std::accumulate(superinc_seq.begin(), superinc_seq.end(), BigInt(0))
            + big_random(inc_digits);
}

BigInt generate_rand_multiplier(const BigInt& m)
{
    BigInt t = m;

    if (t % 2 == 0)
        t--;

    while (gcd(m, t) != 1)
        t -= 2;

    return t;
}

std::vector<BigInt> generate_knapsack_sequence(
        const std::vector<BigInt>& superinc_seq, const BigInt& m,
        const BigInt& t)
{
    std::vector<BigInt> knapsack_seq;
    knapsack_seq.reserve(superinc_seq.size());

    for (const auto& num : superinc_seq) {
        knapsack_seq.push_back((num * t) % m);
    }

    return knapsack_seq;
}

char16_t solve_knapsack(const std::vector<BigInt>& superinc_seq, BigInt s)
{
    char16_t sol = 0;

    for (int i = superinc_seq.size() - 1; i >= 0 && s > 0; i--) {
        if (superinc_seq[i] <= s) {
            sol |= (1 << i);
            s -= superinc_seq[i];
        }
    }
    return sol;
}

}  // namespace petliukh::cryptography
