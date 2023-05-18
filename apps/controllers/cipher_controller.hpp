#include "cipher_base.hpp"

#include <array>
#include <memory>
#include <string>

namespace petliukh::controllers {
namespace cr = petliukh::cryptography;

class Cipher_controller {
public:
    Cipher_controller();

    std::string get_filename() const;
    std::string get_key() const;
    std::string get_lang() const;
    cr::Language get_lang_obj() const;
    std::string get_content(int index) const;
    int get_curr_state() const;

    void set_cipher_index(int idx);
    void set_key(const std::string& key);
    void set_lang(const std::string& lang);
    void set_filename(const std::string& filename);
    void set_content(int index, const std::string& content);
    void set_curr_state(int index);

    std::string read_content_from_file();
    std::string read_key_from_file(const std::string& filename);
    void save_file(int content_index);
    void save_file(const std::string& content);
    void reset();

    std::string encrypt(const std::string& message);
    std::string decrypt(const std::string& message);
    std::string encrypt_raw_bytes(const std::string& bytes);
    std::string decrypt_raw_bytes(const std::string& bytes);
    std::map<char16_t, int> calc_freqs(std::string content);

    std::map<int, std::string> brute_force(const std::string& message);

    std::string
    break_trithemius_cipher_key(std::string enc, std::string dec, int vec_size);
    void generate_rand_keyword(const std::string& filename);
    void
    generate_rand_knapsack_key(const std::string& filename, size_t inc_digits);
    std::string get_knapsack_key() const;

    void generate_rsa_key(const std::string& filename, size_t key_digits);
    std::string get_rsa_key() const;

    std::string diffie_hellman_gen_common_pair();
    std::string diffie_hellman_gen_a_secret();
    std::string diffie_hellman_gen_b_secret();
    std::string diffie_hellman_share_a_side(
            const std::string& g, const std::string& p, const std::string& a);
    std::string diffie_hellman_share_b_side(
            const std::string& g, const std::string& p, const std::string& b);
    std::string calc_common_key_from_b_shared(
            const std::string& shared_b, const std::string& a,
            const std::string& p);
    std::string calc_common_key_from_a_shared(
            const std::string& shared_a, const std::string& b,
            const std::string& p);

private:
    std::array<std::unique_ptr<cr::Cipher>, 4> m_ciphers;
    std::array<std::string, 3> m_content_arr;

    int m_curr_cipher{};
    int m_curr_state{};

    std::string m_filename;
    std::string m_key;
    std::string m_lang;
};

}  // namespace petliukh::controllers
