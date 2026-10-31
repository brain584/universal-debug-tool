cmake_minimum_required(VERSION 3.22.1)
project(zeroptrace GIT NONE CXX)

# 独立构建：零 ptrace 注入器（arm64 可执行文件）
# 用法见 build_zpt.bat

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(zeroptrace_injector zeroptrace_injector.cpp)

target_compile_options(zeroptrace_injector PRIVATE -Wall -Wextra -O2 -fPIE)
target_link_options(zeroptrace_injector PRIVATE -pie)
target_link_libraries(zeroptrace_injector log)
