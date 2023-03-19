cmake_minimum_required(VERSION 3.0)

set(LIB_NAME math-crypto-lib)

add_library(${LIB_NAME} cipher_base.cpp shift_cipher.cpp tritemius_cipher.cpp)

target_include_directories(${LIB_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/include)

find_package(OpenSSL REQUIRED)

target_link_libraries(${LIB_NAME} PUBLIC OpenSSL::Crypto)
