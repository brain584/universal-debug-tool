cmake_minimum_required(VERSION 3.22.1)
project("unversaldebugtool")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 基础路径
set(IMGUI_ROOT   ${CMAKE_CURRENT_SOURCE_DIR}/imgui)
set(IMGUI_INC    ${IMGUI_ROOT}/jni/include)
set(IMGUI_LIBDIR ${IMGUI_ROOT}/obj/local/${ANDROID_ABI})
set(IMGUI_PREBUILT ${IMGUI_ROOT}/prebuilt/${ANDROID_ABI})

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
    ${CMAKE_CURRENT_SOURCE_DIR}/agent/jni
    ${CMAKE_CURRENT_SOURCE_DIR}/agent/jni/luajit/include
    ${CMAKE_CURRENT_SOURCE_DIR}/agent/jni/Dobby
    ${CMAKE_CURRENT_SOURCE_DIR}/agent/jni/memTool
    ${CMAKE_CURRENT_SOURCE_DIR}/agent/jni/xdl
    ${CMAKE_CURRENT_SOURCE_DIR}/agent/jni/lua
)
target_compile_definitions(agent PRIVATE
    LUAJIT_ENABLE_GC64
    LUAJIT_ENABLE_LUA52COMPAT
)
target_link_libraries(agent
    ${CMAKE_CURRENT_SOURCE_DIR}/agent/jni/luajit/lib/${ANDROID_ABI}/libluajit.a
    ${CMAKE_CURRENT_SOURCE_DIR}/agent/jni/Dobby/libdobby.a
    log
    dl
    m
    z
)
target_link_options(agent PRIVATE -static-libstdc++)

# 共享库（JNI 桥 + Dynamic Island UI）
# 编译 JNI 桥接层与用户 UI 源码，链接预编译的 AImGui 静态库进行渲染。
add_library(unversaldebugtool SHARED
    native-lib.cpp
    # AImGui UI 层：Dynamic Island 侧边栏 + 各功能页
    ${IMGUI_ROOT}/jni/src/ui/ui.cpp
    ${IMGUI_ROOT}/jni/src/ui/main_ui.cpp
    ${IMGUI_ROOT}/jni/src/socket/SocketClient.cpp
    ${IMGUI_ROOT}/jni/src/bp/BpService.cpp
)

target_include_directories(unversaldebugtool PRIVATE
    ${IMGUI_INC}
    ${IMGUI_INC}/imgui
    ${IMGUI_INC}/imgui/backends
    ${IMGUI_INC}/ui
    ${IMGUI_ROOT}/jni/src
    ${IMGUI_ROOT}/jni/src/core
    ${IMGUI_ROOT}/jni/src/platform
    ${IMGUI_ROOT}/jni/src/ui
    ${IMGUI_ROOT}/jni/src/socket
    ${CMAKE_CURRENT_SOURCE_DIR}/imgui/jni/capstone/include
    ${CMAKE_CURRENT_SOURCE_DIR}/imgui/jni/asmjit
)

# AsmJit：内存编辑器的 AArch64 文本汇编（imgui 侧）
file(GLOB ASMJIT_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/imgui/jni/asmjit/asmjit/core/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/imgui/jni/asmjit/asmjit/support/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/imgui/jni/asmjit/asmjit/arm/*.cpp
)
target_sources(unversaldebugtool PRIVATE ${ASMJIT_SOURCES})

target_compile_definitions(unversaldebugtool PRIVATE
    SURFACE_LOG_ENABLE=0
    IMGUI_DISABLE_OBSOLETE_FUNCTIONS
    ASMJIT_STATIC
    ASMJIT_NO_X86
)

target_link_libraries(unversaldebugtool
    # 预编译的 AImGui 静态库：
    #   libaimgui_core.a     - renderer_gl、bloom_gl、font、renderer_factory
    #   libaimgui_platform.a - TouchHelperA（提供符号闭合）
    #   libimgui.a           - Dear ImGui 核心 + imgui_impl_opengl3
    ${IMGUI_LIBDIR}/libaimgui_core.a
    ${IMGUI_LIBDIR}/libaimgui_platform.a
    ${IMGUI_PREBUILT}/libimgui.a
    # Capstone：imgui 侧本地反汇编（不占用 socket 通道）
    ${CMAKE_CURRENT_SOURCE_DIR}/imgui/jni/capstone/lib/${ANDROID_ABI}/libcapstone.a
    # Android 系统库
    GLESv3
    EGL
    android
    log
    m
)