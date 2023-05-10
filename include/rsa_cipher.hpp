#include "cipher_base.hpp"
#include "BigInt.hpp"

namespace petliukh::cryptography {

class Rsa_cipher: public Cipher {
public:
    struct Key {
        BigInt p;
        BigInt q;
        BigInt N;
        BigInt phi;
        BigInt e;
        BigInt d;

        std::string to_string() const;
    };

    Rsa_cipher();
    virtual ~Rsa_cipher();
    virtual std::u16string encrypt(const std::u16string& message) override;
    virtual std::u16string decrypt(const std::u16string& message) override;
    virtual std::string encrypt_raw_bytes(const std::string& bytes) override;
    virtual std::string decrypt_raw_bytes(const std::string& bytes) override;
    virtual void set_key(const std::u16string& key) override;
    virtual void set_lang(const std::u16string& lang) override;
    virtual void set_lang(const Language& lang) override;
    Key get_key() const;
    void generate_rand_key(size_t key_digits = 10);

private:

    Key m_key;
};

}  // namespace petliukh::cryptography
