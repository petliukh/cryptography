cmake_minimum_required(VERSION 3.0)

set(LIB_NAME math-crypto-lib)

add_library(${LIB_NAME} cipher_base.cpp shift_cipher.cpp trithemius_cipher.cpp)

target_include_directories(${LIB_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/include)

find_package(OpenSSL REQUIRED)

add_subdirectory(${CMAKE_SOURCE_DIR}/external/eigen
                 ${CMAKE_BINARY_DIR}/external/eigen)

target_link_libraries(${LIB_NAME} PUBLIC OpenSSL::Crypto Eigen3::Eigen)
