#!/bin/bash

if [ -z "$NDK_HOME" ]; then
    echo "Error: NDK_HOME is not set"
    exit 1
fi

BUILD_DIR="build"
ABI="arm64-v8a"
API=21

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake .. \
    -DCMAKE_TOOLCHAIN_FILE="$NDK_HOME/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI="$ABI" \
    -DANDROID_PLATFORM="android-$API" \
    -DCMAKE_BUILD_TYPE=Release \
    -G "Ninja"

if [ $? -ne 0 ]; then
    echo "CMake configuration failed"
    exit 1
fi

ninja

if [ $? -ne 0 ]; then
    echo "Build failed"
    exit 1
fi

echo ""
echo "Build successful!"
echo "Output: $BUILD_DIR/injector"
