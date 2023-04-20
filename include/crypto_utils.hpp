#pragma once
#include <string>

namespace petliukh::cryptography {

std::string sha256(const std::string& str);
std::string sha256(const std::u16string& str);
int rand(int a, int b);

}
