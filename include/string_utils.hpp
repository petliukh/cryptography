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
std::vector<std::u16string> str_split(const std::u16string& u16str, char delimiter);

template<typename T>
std::string vec_to_string(const std::vector<T>& vec)
{
    std::stringstream ss;
    for (int i = 0; i < vec.size(); i++) {
        ss << vec[i];
        if (i != vec.size() - 1)
            ss << ", ";
    }
    return ss.str();
}

std::vector<int64_t> str_to_vec_i64(const std::string& str);

}  // namespace petliukh::cryptography
