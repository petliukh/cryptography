#pragma once
#include <string>
#include <limits>
#include <InfInt.h>

namespace petliukh::cryptography {

std::string sha256(const std::string& str);
std::string sha256(const std::u16string& str);
int randint(int a, int b);
InfInt infint_rand(size_t num_digits);

}
