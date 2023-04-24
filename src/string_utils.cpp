#include "string_utils.hpp"

namespace petliukh::cryptography {

std::string utf16_to_utf8(const std::u16string& utf16)
{
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> conv;
    std::string utf8 = conv.to_bytes(utf16);
    return utf8;
}

std::u16string utf8_to_utf16(const std::string& utf8)
{
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> conv;
    std::u16string utf16 = conv.from_bytes(utf8);
    return utf16;
}

std::vector<std::string> str_split(const std::string& str, char delimiter)
{
    std::vector<std::string> result;
    std::stringstream ss(str);
    std::string item;
    while (std::getline(ss, item, delimiter)) {
        result.push_back(item);
    }
    return result;
}

std::vector<std::u16string> str_split(const std::u16string& u16str, char delimiter)
{
    std::vector<std::u16string> result;
    std::string str = utf16_to_utf8(u16str);
    std::stringstream ss(str);
    std::string item;
    while (std::getline(ss, item, delimiter)) {
        result.push_back(utf8_to_utf16(item));
    }
    return result;
}

std::vector<int64_t> str_to_vec_i64(const std::string& str)
{
    auto parts = str_split(str, ' ');
    std::vector<int64_t> ints;
    ints.reserve(parts.size());
    for (auto& p: parts) {
        ints.push_back(std::stol(p));
    }
    return ints;
}

}  // namespace petliukh::cryptography
