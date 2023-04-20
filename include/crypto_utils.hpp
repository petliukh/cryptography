#pragma once
#include <string>
#include <limits>

namespace petliukh::cryptography {

std::string sha256(const std::string& str);
std::string sha256(const std::u16string& str);
int rand_in_rng(int a = 0, int b = std::numeric_limits<int>::max());

}
