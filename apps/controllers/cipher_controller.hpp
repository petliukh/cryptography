#include "crypto_ciphers.hpp"

#include <array>
#include <memory>

namespace petliukh::controllers {

namespace cr = petliukh::cryptography;

class cipher_controller {
public:
    cipher_controller();

    // Misc

    void set_cipher(int idx);

    void set_key(const std::string& key);

    void set_lang(const std::string& lang);

    void set_filename(const std::string& filename);

    void read_file();

    std::string get_filename() const;

    std::string get_filecontent() const;

    void set_filecontent(const std::string& content);

    void save_file();

    // Cipher methods

    std::string encrypt(const std::string& message);

    std::string decrypt(const std::string& message);

    std::string encrypt_raw_bytes(const std::string& bytes);

    std::string decrypt_raw_bytes(const std::string& bytes);

private:
    std::array<std::unique_ptr<cr::cipher>, 2> m_ciphers;
    int m_curr_idx;
    std::string m_filename;
    std::string m_filecontent;
};

}  // namespace petliukh::controllers
