#include "numeric_utils.hpp"

#include <vector>

namespace petliukh::cryptography {

bool is_prime(const BigInt& n)
{
    BigInt n_sqrt = sqrt(n);

    if (n % 2 == 0)
        return false;

    for (BigInt i = 3; i <= n_sqrt; i += 2) {
        if (n % i == 0) {
            return false;
        }
    }

    return true;
}

// Function to return nearest prime number
BigInt nearest_prime(BigInt n)
{
    // All prime numbers are odd except two
    if (n % 2 == 0)
        n -= 2;
    else
        n--;

    BigInt i, j;
    for (i = n; i >= 2; i -= 2) {
        if (i % 2 == 0)
            continue;
        for (j = 3; j <= sqrt(i); j += 2) {
            if (i % j == 0)
                break;
        }
        if (j > sqrt(i))
            return i;
    }
    // It will only be executed when n is 3
    return 2;
}

BigInt mod_exp(const BigInt& a, BigInt e, const BigInt& m)
{
    std::vector<BigInt> mods;
    std::vector<BigInt> pows;
    mods.push_back(a % m);
    pows.push_back(1);

    while (pows.back() < e) {
        mods.push_back((mods.back() * mods.back()) % m);
        pows.push_back(pows.back() * 2);
    }
    BigInt mod = 1;

    for (int i = mods.size() - 1; i >= 0; i--) {
        if (e >= pows[i]) {
            mod *= mods[i];
            e -= pows[i];
        }
    }
    return mod % m;
}

}  // namespace petliukh::cryptography
