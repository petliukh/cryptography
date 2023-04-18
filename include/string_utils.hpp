#pragma once
#include <string>
#include <sstream>
#include <codecvt>
#include <locale>
#include <vector>

namespace petliukh::string_utils {

std::string utf16_to_utf8(const std::u16string& utf16);
std::u16string utf8_to_utf16(const std::string& utf8);
std::vector<std::string> str_split(const std::string& str, char delimiter);

}
