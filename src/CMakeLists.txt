cmake_minimum_required(VERSION 3.0)

set(LIB_NAME math-crypto-lib)
set(SOURCES
    cipher_base.cpp
    shift_cipher.cpp
    trithemius_cipher.cpp
    string_utils.cpp
    crypto_utils.cpp
    numeric_utils.cpp
    knapsack_cipher.cpp
    rsa_cipher.cpp
    BigInt.cpp)

add_library(${LIB_NAME} ${SOURCES})
add_subdirectory(${CMAKE_SOURCE_DIR}/external/eigen
                 ${CMAKE_BINARY_DIR}/external/eigen)
find_package(OpenSSL REQUIRED)
target_include_directories(${LIB_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(${LIB_NAME} PUBLIC OpenSSL::Crypto Eigen3::Eigen)
