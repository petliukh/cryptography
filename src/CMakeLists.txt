cmake_minimum_required(VERSION 3.0)

set(LIB_NAME math-crypto-lib)

add_library(${LIB_NAME} shift_cipher.cpp)

target_include_directories(${LIB_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/include)
