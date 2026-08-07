#include "renderer.h"

#include <android/log.h>

#define LOG_TAG "AImGui"
#define LOGI(fmt, ...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, fmt, ##__VA_ARGS__)

namespace aimgui {

std::unique_ptr<IRenderer> MakeRenderer(ANativeWindow* window,
                                        int width, int height,
                                        Backend preferred) {
    auto tryInit = [&](std::unique_ptr<IRenderer> r) -> std::unique_ptr<IRenderer> {
        if (!r) return nullptr;
        if (r->Init(window, width, height)) {
            LOGI("renderer: %s", r->Name());
            return r;
        }
        r->Shutdown();
        return nullptr;
    };

    if (preferred == Backend::OpenGL) return tryInit(MakeGLRenderer());
    if (preferred == Backend::Vulkan) return tryInit(MakeVKRenderer());

    if (auto vk = tryInit(MakeVKRenderer())) return vk;
    LOGW("Vulkan init failed, falling back to OpenGL ES 3");
    return tryInit(MakeGLRenderer());
}

} // namespace aimgui
