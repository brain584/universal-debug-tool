cmake_minimum_required(VERSION 3.10)


# 如果未设置 NDK 路径，尝试从环境变量获取
if(NOT DEFINED CMAKE_ANDROID_NDK)
    set(CMAKE_ANDROID_NDK D:/ndkollvm/android-ndk-r27c-windows/android-ndk-r27c)
endif()

if(CMAKE_ANDROID_NDK AND NOT CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE ${CMAKE_ANDROID_NDK}/build/cmake/android.toolchain.cmake)
endif()

# Android NDK 设置
set(CMAKE_SYSTEM_NAME Android)
set(CMAKE_SYSTEM_VERSION 28)
set(ANDROID_ABI arm64-v8a)
set(ANDROID_PLATFORM android-26)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

project(newInjector LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 只支持 ARM64
if(ANDROID AND NOT CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a")
    message(FATAL_ERROR "This project only supports arm64-v8a")
endif()

set(SOURCES
    src/main.cpp
    src/Injector.cpp
    src/RemoteProcess.cpp
    src/ElfParser.cpp
    src/Utils.cpp
    src/SolistHider.cpp
    src/ProcessMonitor.cpp
)

add_executable(injector ${SOURCES})

target_include_directories(injector PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_options(injector PRIVATE
    -Wall -Wextra -fPIE
)

target_link_options(injector PRIVATE
    -pie
)

if(ANDROID)
    target_link_libraries(injector log)
endif()
