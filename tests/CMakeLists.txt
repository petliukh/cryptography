# Set the minimum required version of CMake
cmake_minimum_required(VERSION 3.0)

# Set the name of the test executable
set(TEST_NAME math-crypto-tests)

# Add all source files to the test executable target
add_executable(${TEST_NAME} shift_cipher_tests.cpp)

# Include the googletest directory and specify its binary directory
add_subdirectory(${CMAKE_SOURCE_DIR}/external/googletest
                 ${CMAKE_BINARY_DIR}/external/googletest)

# Link the test executable with the library target
target_link_libraries(${TEST_NAME} math-crypto-lib)

# Link the test executable with the gtest and gtest_main libraries
target_link_libraries(${TEST_NAME} gtest gtest_main)

# Add a test for the test executable
add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
