#pragma once
#include <algorithm>
#include <map>
#include <vector>

namespace petliukh::cryptography {
template<typename A, typename B>
std::pair<B, A> flip_pair(const std::pair<A, B>& p)
{
    return std::pair<B, A>(p.second, p.first);
}

template<typename A, typename B>
std::multimap<B, A> flip_map(const std::map<A, B>& src)
{
    std::multimap<B, A> dst;
    std::transform(
            src.begin(), src.end(), std::inserter(dst, dst.begin()),
            flip_pair<A, B>);
    return dst;
}

template<typename A, typename B>
std::vector<std::pair<A, B>> vec_from_map(const std::map<A, B>& src)
{
    std::vector<std::pair<A, B>> res;
    res.reserve(src.size());
    std::copy(src.begin(), src.end(), std::back_inserter(res));
    return res;
}

}  // namespace petliukh::cryptography
