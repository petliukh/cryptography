cmake_minimum_required(VERSION 3.0)

set(TEST_NAME math-crypto-tests)
set(SOURCES cipher_base_tests.cpp shift_cipher_tests.cpp
            trithemius_cipher_tests.cpp knapsack_cipher_tests.cpp
            rsa_cipher_tests.cpp)

add_executable(${TEST_NAME} ${SOURCES})
add_subdirectory(${CMAKE_SOURCE_DIR}/external/googletest
                 ${CMAKE_BINARY_DIR}/external/googletest)
add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
target_link_libraries(${TEST_NAME} math-crypto-lib)
target_link_libraries(${TEST_NAME} gtest gtest_main)
