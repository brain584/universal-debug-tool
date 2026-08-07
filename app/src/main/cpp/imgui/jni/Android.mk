LOCAL_PATH := $(call my-dir)

# ----------------------------------------------------------------------
# 预编译静态库 libimgui.a
# ----------------------------------------------------------------------
include $(CLEAR_VARS)
LOCAL_MODULE := imgui
LOCAL_SRC_FILES := ../prebuilt/$(TARGET_ARCH_ABI)/libimgui.a
LOCAL_EXPORT_C_INCLUDES := \
    $(LOCAL_PATH)/include/imgui \
    $(LOCAL_PATH)/include/imgui/backends
include $(PREBUILT_STATIC_LIBRARY)

# ----------------------------------------------------------------------
# 静态库 aimgui_platform
# ----------------------------------------------------------------------
include $(CLEAR_VARS)
LOCAL_MODULE := aimgui_platform
LOCAL_SRC_FILES := src/platform/TouchHelperA.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)/src
LOCAL_STATIC_LIBRARIES := imgui
LOCAL_CPPFLAGS := -std=c++17 -fno-rtti \
                  -Os -ffunction-sections -fdata-sections \
                  -fvisibility=hidden -fvisibility-inlines-hidden \
                  -fno-unwind-tables -fno-asynchronous-unwind-tables
LOCAL_CFLAGS   := -DSURFACE_LOG_ENABLE=0
include $(BUILD_STATIC_LIBRARY)

# ----------------------------------------------------------------------
# 静态库 aimgui_core
# ----------------------------------------------------------------------
include $(CLEAR_VARS)
LOCAL_MODULE := aimgui_core
LOCAL_SRC_FILES := \
    src/core/renderer_factory.cpp \
    src/core/renderer_gl.cpp \
    src/core/renderer_vk.cpp \
    src/core/vulkan_wrapper.cpp \
    src/core/bloom_gl.cpp \
    src/core/bloom_vk.cpp \
    src/core/font.cpp \
    src/core/keyboard_input.cpp \
    src/core/window_session.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)/src $(LOCAL_PATH)/include
LOCAL_STATIC_LIBRARIES := imgui aimgui_platform
LOCAL_CPPFLAGS := -std=c++17 -fno-rtti \
                  -Os -ffunction-sections -fdata-sections \
                  -fvisibility=hidden -fvisibility-inlines-hidden \
                  -fno-unwind-tables -fno-asynchronous-unwind-tables
LOCAL_CFLAGS   := -DSURFACE_LOG_ENABLE=0 \
                  -DVK_USE_PLATFORM_ANDROID_KHR \
                  -DIMGUI_IMPL_VULKAN_NO_PROTOTYPES
include $(BUILD_STATIC_LIBRARY)

# ----------------------------------------------------------------------
# 可执行文件 AImGui
# ----------------------------------------------------------------------
include $(CLEAR_VARS)
LOCAL_MODULE := AImGui
LOCAL_SRC_FILES := \
    src/main.cpp \
    src/ui/ui.cpp \
    src/ui/main_ui.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include $(LOCAL_PATH)/src
LOCAL_STATIC_LIBRARIES := aimgui_core aimgui_platform imgui   # ← 已移除 c++_static
LOCAL_LDLIBS := -llog -landroid -lEGL -lGLESv3 -lm
LOCAL_CPPFLAGS := -std=c++17 -fno-rtti \
                  -Os -ffunction-sections -fdata-sections \
                  -fvisibility=hidden -fvisibility-inlines-hidden \
                  -fno-unwind-tables -fno-asynchronous-unwind-tables
LOCAL_CFLAGS   := -DSURFACE_LOG_ENABLE=0
LOCAL_LDFLAGS  := -Wl,--gc-sections -Wl,--icf=all -Wl,-s
include $(BUILD_EXECUTABLE)