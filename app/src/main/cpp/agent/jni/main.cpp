// Agent 载荷——由注入器注入到目标进程中。
//
// 构造函数启动加密 socket 服务端（见 socket/socket.cpp）：
// imgui 悬浮层连接它并交换加密命令 / 事件。
// 注入器以 reserved = 1337 调用 JNI_OnLoad。
//
#include <jni.h>
#include <android/log.h>
#include <unistd.h>

#include "socket/socket.h"
#include "lua/LuaEngine.h"

#define LOG_TAG "Agent"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

constexpr int INJECTOR_SECRET_KEY = 1337;

__attribute__((constructor))
static void OnAgentLoad() {
    LOGI("Agent loaded into pid=%d (constructor)", getpid());
    // 先启动 socket 服务端，即使 Lua
    // 引擎初始化在异常目标进程中变慢或卡住，通道也保持可用。
    int rc = AgentSocketStart();
    LOGI("Agent socket server start rc=%d", rc);
    LuaEngine::Init();
    LOGI("Agent Lua engine init done");
}

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGI("Agent JNI_OnLoad vm=%p reserved=%p", vm, reserved);
    if (reserved == reinterpret_cast<void*>(INJECTOR_SECRET_KEY)) {
        LOGI("Agent: injected by universal_debug_tool");
    }
    // 备用：注入器在 dlopen 后会调用 JNI_OnLoad，因此在构造函数
    // 被跳过或崩溃时，这里也启动 socket 服务端。
    // AgentSocketStart 是幂等的。
    int rc = AgentSocketStart();
    LOGI("Agent socket server start (JNI_OnLoad) rc=%d", rc);
    return JNI_VERSION_1_6;
}
