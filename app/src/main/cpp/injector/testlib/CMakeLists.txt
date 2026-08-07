cmake_minimum_required(VERSION 3.10)
project(testlib LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

add_library(testlib SHARED testlib.cpp)

target_link_libraries(testlib log)
