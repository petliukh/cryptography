#include "knapsack_cipher.hpp"

#include "crypto_utils.hpp"

#include <algorithm>

namespace petliukh::cryptography {

std::u16string Knapsack_cipher::encrypt(const std::u16string& message)
{
    return u"";
}

std::u16string Knapsack_cipher::decrypt(const std::u16string& message)
{
    return u"";
}

std::string Knapsack_cipher::encrypt_raw_bytes(const std::string& bytes)
{
    return "";
}

std::string Knapsack_cipher::decrypt_raw_bytes(const std::string& bytes)
{
    return "";
}

void Knapsack_cipher::set_key(const std::u16string& key)
{
}

void Knapsack_cipher::set_lang(const std::u16string& lang)
{
}

void Knapsack_cipher::set_lang(const Language& lang)
{
}

std::vector<int> generate_supergrowing_sequence(int n)
{
    std::vector<int> supergrow_seq;
    supergrow_seq.reserve(n);
    int prev_sum = 0;

    for (int i = 0; i < n; i++) {
        supergrow_seq.emplace_back(prev_sum + rand());
        prev_sum += supergrow_seq.back();
    }
    return supergrow_seq;
}

}  // namespace petliukh::cryptography
