#include "rsa_cipher.hpp"

#include "numeric_utils.hpp"
#include "string_utils.hpp"
#include <cassert>

namespace petliukh::cryptography {

Rsa_cipher::Rsa_cipher()
{
}

Rsa_cipher::~Rsa_cipher()
{
}

std::u16string Rsa_cipher::encrypt(const std::u16string& message)
{
    std::stringstream ss;

    for (int i = 0; i < message.size(); i++) {
        BigInt enc_chr(static_cast<int16_t>(message[i]));
        enc_chr = mod_exp(enc_chr, m_key.e, m_key.N);
        ss << enc_chr;

        if (i != message.size() - 1)
            ss << " ";
    }

    return utf8_to_utf16(ss.str());
}

std::u16string Rsa_cipher::decrypt(const std::u16string& message)
{
    std::vector<std::string> ciphertex = str_split(utf16_to_utf8(message), ' ');
    std::u16string plaintext;

    for (const std::string& num: ciphertex) {
        BigInt c(num);
        BigInt dec = mod_exp(c, m_key.d, m_key.N);
        char16_t chr = static_cast<char16_t>(dec.to_int());
        plaintext += chr;
    }
    return plaintext;
}

std::string Rsa_cipher::encrypt_raw_bytes(const std::string& bytes)
{
    return "";
}

std::string Rsa_cipher::decrypt_raw_bytes(const std::string& bytes)
{
    return "";
}

void Rsa_cipher::set_key(const std::u16string& key)
{
    std::vector<std::string> primes = str_split(utf16_to_utf8(key), ' ');

    m_key.p = BigInt(primes[0]);
    m_key.q = BigInt(primes[1]);

    m_key.N = m_key.p * m_key.q;
    m_key.phi = (m_key.p - 1) * (m_key.q - 1);
    m_key.e = 2;

    while ((gcd(m_key.e, m_key.N) != 1 || gcd(m_key.e, m_key.phi) != 1)
           && m_key.e < m_key.phi) {
        m_key.e++;
    }

    m_key.d = mod_inverse(m_key.e, m_key.phi);
}

Rsa_cipher::Key Rsa_cipher::get_key() const
{
    return m_key;
}

std::string Rsa_cipher::Key::to_string() const
{
    std::stringstream ss;
    ss << p << " " << q;
    return ss.str();
}

void Rsa_cipher::set_lang(const std::u16string& lang)
{
}

void Rsa_cipher::set_lang(const Language& lang)
{
}

void Rsa_cipher::generate_rand_key(size_t key_digits)
{
    m_key.p = big_random(key_digits);
    m_key.q = big_random(key_digits);

    if (m_key.p % 2 == 0)
        m_key.p--;
    if (m_key.q % 2 == 0)
        m_key.q--;

    while (!is_prime(m_key.p)) {
        m_key.p -= 2;
    }
    while (!is_prime(m_key.q)) {
        m_key.q -= 2;
    }
    m_key.N = m_key.p * m_key.q;
    m_key.phi = (m_key.p - 1) * (m_key.q - 1);
    m_key.e = 2;

    while ((gcd(m_key.e, m_key.N) != 1 || gcd(m_key.e, m_key.phi) != 1)
           && m_key.e < m_key.phi) {
        m_key.e++;
    }

    m_key.d = mod_inverse(m_key.e, m_key.phi);
}

}  // namespace petliukh::cryptography
