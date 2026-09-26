cmake_minimum_required(VERSION 3.22.1)
project("unversaldebugtool")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 基础路径
set(CPP_ROOT     ${CMAKE_CURRENT_SOURCE_DIR})
set(BACKEND_ROOT ${CPP_ROOT}/backend)
set(BACKEND_SRC  ${BACKEND_ROOT}/jni/src)

# Agent 注入载荷（注入到目标进程）
# 会打包进 APK 作为 libagent.so，由应用注入到用户选择的进程。
# 使用 -static-libstdc++ 避免依赖 libc++_shared.so，
# 这样目标进程无需额外依赖即可 dlopen 加载。
add_library(agent SHARED
    agent/jni/main.cpp
    agent/jni/socket/socket.cpp
    agent/jni/xdl/xdl.c
    agent/jni/xdl/xdl_iterate.c
    agent/jni/xdl/xdl_linker.c
    agent/jni/xdl/xdl_lzma.c
    agent/jni/xdl/xdl_util.c
)
target_include_directories(agent PRIVATE
    ${CPP_ROOT}/agent/jni
    ${CPP_ROOT}/agent/jni/luajit/include
    ${CPP_ROOT}/agent/jni/Dobby
    ${CPP_ROOT}/agent/jni/memTool
    ${CPP_ROOT}/agent/jni/xdl
    ${CPP_ROOT}/agent/jni/lua
)
target_compile_definitions(agent PRIVATE
    LUAJIT_ENABLE_GC64
    LUAJIT_ENABLE_LUA52COMPAT
)
target_link_libraries(agent
    ${CPP_ROOT}/agent/jni/luajit/lib/${ANDROID_ABI}/libluajit.a
    ${CPP_ROOT}/agent/jni/Dobby/libdobby.a
    log
    dl
    m
    z
)
target_link_options(agent PRIVATE -static-libstdc++)

# 共享库：JNI 后端 + 原生悬浮窗桥接 + 后端复用
# （内存搜索 memorysearch / 断点 BpService / socket / 反汇编 Disasm / 汇编 AsmWrite）。
add_library(unversaldebugtool SHARED
    native-lib.cpp
    overlay_bridge.cpp
    ${BACKEND_SRC}/socket/SocketClient.cpp
    ${BACKEND_SRC}/bp/BpService.cpp
    # MemorySearch：内存读写 / 搜索库（MIT，已去除 Keystone 依赖）
    ${BACKEND_ROOT}/jni/memsearch/Mem.cpp
    ${BACKEND_ROOT}/jni/memsearch/Membase.cpp
    ${BACKEND_ROOT}/jni/memsearch/MemMmap.cpp
    ${BACKEND_ROOT}/jni/memsearch/MemSu.cpp
    ${BACKEND_ROOT}/jni/memsearch/Process.cpp
    ${BACKEND_ROOT}/jni/memsearch/ProcIO.cpp
    ${BACKEND_ROOT}/jni/memsearch/Search.cpp
    ${BACKEND_ROOT}/jni/memsearch/FuzzySearch.cpp
)

target_include_directories(unversaldebugtool PRIVATE
    ${BACKEND_SRC}
    ${BACKEND_SRC}/ui
    ${BACKEND_ROOT}/jni/memsearch
    ${BACKEND_ROOT}/jni/capstone/include
    ${BACKEND_ROOT}/jni/asmjit
)

# AsmJit：内存编辑器的 AArch64 文本汇编
file(GLOB ASMJIT_SOURCES
    ${BACKEND_ROOT}/jni/asmjit/asmjit/core/*.cpp
    ${BACKEND_ROOT}/jni/asmjit/asmjit/support/*.cpp
    ${BACKEND_ROOT}/jni/asmjit/asmjit/arm/*.cpp
)
target_sources(unversaldebugtool PRIVATE ${ASMJIT_SOURCES})

target_compile_definitions(unversaldebugtool PRIVATE
    ASMJIT_STATIC
    ASMJIT_NO_X86
)

target_link_libraries(unversaldebugtool
    # Capstone：本地反汇编（不占用 socket 通道）
    ${BACKEND_ROOT}/jni/capstone/lib/${ANDROID_ABI}/libcapstone.a
    # Android 系统库
    log
    m
)
