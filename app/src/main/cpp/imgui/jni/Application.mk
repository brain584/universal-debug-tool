APP_ABI := arm64-v8a
APP_STL := c++_static
APP_PLATFORM := android-24
APP_CPPFLAGS := -std=c++17 -fno-rtti -Os -ffunction-sections -fdata-sections \
                -fvisibility=hidden -fvisibility-inlines-hidden \
                -fno-unwind-tables -fno-asynchronous-unwind-tables
APP_CFLAGS   := -DSURFACE_LOG_ENABLE=0
APP_LDFLAGS  := -Wl,--gc-sections -Wl,--icf=all -Wl,-s