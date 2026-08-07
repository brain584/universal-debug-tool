#include <jni.h>
#include <android/log.h>
#include <thread>
#include <chrono>

#define LOG_TAG "TestLib"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// 注入器使用的密钥
constexpr int INJECTOR_SECRET_KEY = 1337;

// 构造函数 - 不要在这里启动线程
__attribute__((constructor))
void onLoad() {
    LOGI("Library loaded (constructor)");
}

// 工作线程
void workerThread() {
    LOGI("Worker thread started");
    
    for (int i = 0; i < 10; ++i) {
        LOGI("Worker tick: %d", i);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    LOGI("Worker thread finished");
}

// JNI 入口点
extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGI("========================================");
    LOGI("JNI_OnLoad called");
    LOGI("JavaVM: %p", vm);
    LOGI("Reserved/Key: %p", reserved);
    
    // 检查是否由注入器调用
    if (reserved != reinterpret_cast<void*>(INJECTOR_SECRET_KEY)) {
        LOGI("Not called by injector, normal load");
        return JNI_VERSION_1_6;
    }
    
    LOGI("Called by injector!");
    
    // 获取 JNIEnv
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK) {
        LOGI("JNIEnv: %p", env);
    } else {
        LOGI("Failed to get JNIEnv");
    }
    
    // 启动工作线程
    std::thread(workerThread).detach();
    
    LOGI("========================================");
    return JNI_VERSION_1_6;
}
