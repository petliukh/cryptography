#pragma once
#include <string>
#include <openssl/sha.h>

namespace petliukh::cryptography {

std::string sha256(const std::string& str);
std::string sha256(const std::u16string& str);

}
