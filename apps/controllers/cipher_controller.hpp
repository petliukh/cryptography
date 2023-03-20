#include "crypto_ciphers.hpp"

#include <array>
#include <memory>

namespace petliukh::controllers {

namespace cr = petliukh::cryptography;

class cipher_controller {
public:
    cipher_controller();

    // Getters
    std::string get_filename() const;

    std::string get_key() const;

    std::string get_lang() const;

    std::string get_content(int index) const;

    int get_curr_state() const;

    // Setters
    void set_cipher_index(int idx);

    void set_key(const std::string& key);

    void set_lang(const std::string& lang);

    void set_filename(const std::string& filename);

    void set_content(int index, const std::string& content);

    void set_curr_state(int index);

    // Misc
    std::string read_file();

    void save_file(int content_index);

    void save_file(const std::string& content);

    void reset();

    // Cipher methods

    std::string encrypt(const std::string& message);

    std::string decrypt(const std::string& message);

    std::string encrypt_raw_bytes(const std::string& bytes);

    std::string decrypt_raw_bytes(const std::string& bytes);

    std::unordered_map<char16_t, int> calc_freqs(int content_index);

private:
    std::array<std::unique_ptr<cr::cipher>, 2> m_ciphers;
    std::array<std::string, 3> m_content_arr;

    int m_curr_cipher{};
    int m_curr_state{};

    std::string m_filename;
    std::string m_key;
    std::string m_lang;
};

}  // namespace petliukh::controllers
