#pragma once
#include <algorithm>
#include <cstdint>

namespace petliukh::cryptography {

template<typename Int_type>
struct Ext_euclidean_res {
    Int_type s;
    Int_type t;
    Int_type old_s;
    Int_type old_t;
    Int_type gcd;
};

template<typename Int_type>
Int_type gcd(Int_type a, Int_type b)
{
    if (a < b)
        std::swap(a, b);

    while (b != 0) {
        Int_type t = b;
        b = a % b;
        a = t;
    }
    return a;
}

template<typename Int_type>
Ext_euclidean_res<Int_type> ext_euclidean(Int_type a, Int_type m)
{
    if (a < m)
        std::swap(a, m);

    Int_type q, r;
    Int_type s = 0, s_prev = 1;
    Int_type t = 1, t_prev = 0;

    while (m > 0) {
        Int_type tmp = m;
        q = a / m;
        r = a % m;
        m = r;
        a = tmp;

        Int_type s_tmp = s;
        s = s_prev - q * s;
        s_prev = s_tmp;

        Int_type t_tmp = t;
        t = t_prev - q * t;
        t_prev = t_tmp;
    }
    return { s, t, s_prev, t_prev, m };
}

template<typename Int_type>
Int_type modulo(Int_type n, Int_type p)
{
    Int_type r = n % p;
    if (((p > 0) && (r < 0)) || ((p < 0) && (r > 0)))
        r += p;
    return r;
}

template<typename Int_type>
Int_type mod_inverse(Int_type n, Int_type p)
{
    n = modulo(n, p);
    for (int32_t x = 1; x < p; x++) {
        if (modulo(n * x, p) == 1)
            return x;
    }
    return 0;
}

}  // namespace petliukh::cryptography
