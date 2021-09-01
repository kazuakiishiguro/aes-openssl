cmake_minimum_required(VERSION 3.8)

project(aes-openssl)

add_executable(main main.cpp)

set(CMAKE_CXX_FLAGS "-std=c++17")

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
