#pragma once
#include <codecvt>
#include <locale>
#include <sstream>
#include <string>
#include <vector>

namespace petliukh::cryptography {

std::string utf16_to_utf8(const std::u16string& utf16);
std::u16string utf8_to_utf16(const std::string& utf8);
std::vector<std::string> str_split(const std::string& str, char delimiter);

}  // namespace petliukh::cryptography
