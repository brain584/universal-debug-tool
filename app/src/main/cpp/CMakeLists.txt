cmake_minimum_required(VERSION 3.22.1)
project("unversaldebugtool")

# 新增（2026-10-30，P1-13 on-leave 底层）：启用 ASM 语言。
# agent 的跳板模板 agent/jni/arthook/OnLeaveStub.S 需要按 ASM 语言编译；
# project() 默认只启用 C/CXX，不 enable_language(ASM) 时 CMake 会在 generate 阶段
# 报 “Missing variable is: CMAKE_ASM_COMPILE_OBJECT”（已用 NDK30 + cmake 3.22.1 实测）。
# 这只是追加一种语言，不改变其它 target 的编译/链接配置。
enable_language(ASM)

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
    agent/jni/arthook/ArtHook.cpp
    agent/jni/arthook/OnLeave.cpp
    agent/jni/arthook/OnLeaveStub.S
    agent/jni/main.cpp
    agent/jni/socket/socket.cpp
    agent/jni/xdl/xdl.c
    agent/jni/xdl/xdl_iterate.c
    agent/jni/xdl/xdl_linker.c
    agent/jni/xdl/xdl_lzma.c
    agent/jni/xdl/xdl_util.c
)
# OnLeaveStub.S：on-leave 跳板模板（GNU 语法 arm64 汇编），显式按 ASM 语言编译，
# 由 clang 集成汇编器处理（见文件头注释；C++ 侧用符号偏移 patch 模板）。
set_source_files_properties(agent/jni/arthook/OnLeaveStub.S PROPERTIES LANGUAGE ASM)
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
set(LS_ROOT ${CPP_ROOT}/agent/jni/third_party/lsplant)
target_include_directories(agent PRIVATE ${LS_ROOT}/include)
target_compile_features(agent PRIVATE cxx_std_20)
target_link_libraries(agent
    ${LS_ROOT}/lib/${ANDROID_ABI}/liblsplant.a
    ${LS_ROOT}/lib/${ANDROID_ABI}/libdex_builder.a
    ${LS_ROOT}/lib/${ANDROID_ABI}/libstd_modules.a
)
target_compile_options(agent PRIVATE -fvisibility=hidden -fvisibility-inlines-hidden)
# P1-22：保留帧指针。nativeBacktrace 以 x29 链为主路径（LuaJIT 汇编帧没有 CFI，
# .eh_frame 展开会断在 LuaJIT 边界）。Android arm64 的原生 .so 普遍保留帧指针，
# agent 自己也必须保留，否则自己这几帧就断了。
target_compile_options(agent PRIVATE -fno-omit-frame-pointer)
target_link_options(agent PRIVATE
    -static-libstdc++
    -Wl,--exclude-libs,ALL
    -Wl,--version-script=${CPP_ROOT}/agent/jni/agent.map)


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
    # SuBridge.h：统一的 su 入口（BpService / SocketClient 与 native-lib 共用）。
    # 2026-10-10 新增，见 injector/include/SuBridge.h 里的说明。
    ${CPP_ROOT}/injector/include
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
