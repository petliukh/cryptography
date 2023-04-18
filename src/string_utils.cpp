#include "string_utils.hpp"

namespace petliukh::string_utils {

std::string utf16_to_utf8(const std::u16string& utf16) {
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> conv;
    std::string utf8 = conv.to_bytes(utf16);
    return utf8;
}

std::u16string utf8_to_utf16(const std::string& utf8) {
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

}  // namespace petliukh::string_utils
