#pragma once

#include <stdexcept>
namespace petliukh::cryptography {

// Function for extended Euclidean Algorithm
template<typename Int_type>
Int_type gcd_extended(Int_type a, Int_type b, Int_type* x, Int_type* y)
{
    // Base Case
    if (a == 0) {
        *x = 0, *y = 1;
        return b;
    }

    // To store results of recursive call
    Int_type x1, y1;
    Int_type gcd = gcd_extended(b % a, a, &x1, &y1);

    // Update x and y using results of recursive
    // call
    *x = y1 - (b / a) * x1;
    *y = x1;

    return gcd;
}

// Function to find modulo inverse of a
template<typename Int_type>
Int_type mod_inverse(Int_type A, Int_type M)
{
    Int_type x, y;
    Int_type g = gcd_extended(A, M, &x, &y);

    if (g != 1)
        throw std::invalid_argument("Modular inverse does not exist.");
    else {
        // m is added to handle negative x
        return (x % M + M) % M;
    }
}

}  // namespace petliukh::cryptography
