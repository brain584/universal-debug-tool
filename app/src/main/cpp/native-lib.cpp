//
// JNI 桥——Android SurfaceView -> AImGui 渲染器
//
// 无需 root 即可工作：从 Android 的 Surface 获取 ANativeWindow，
// 通过预编译的 aimgui 渲染器创建 EGL 上下文，
// 通过 Android 标准 MotionEvent / IME 处理触摸 / 按键输入。
//
// v3（单窗口悬浮层）：
//  - 不再有全屏窗口。SurfaceView 位于
//    与触摸处理相同的面板大小窗口内，因此屏幕其余部分
//    上面完全没有窗口覆盖，永远不会被拦截，
//    无论 ROM 对悬浮窗口如何处理。
//  - ImGui 窗口锚定在 Surface 原点 (0,0) 并铺满
//    整个屏幕。移动面板 = 移动悬浮窗口（Java）。
//  - 屏幕坐标（rawX/rawY）通过窗口真实的屏幕位置和尺寸
//    转换为 ImGui / Surface 坐标系。
//
#include <jni.h>
#include <android/log.h>
#include <android/native_window.h>
#include <android/native_window_jni.h>
#include <android/keycodes.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <memory>

#include "imgui.h"

#include "core/renderer.h"
#include "core/font.h"
#include "core/frame_pacer.h"
#include "ui/ui.h"

#include "socket/socket.h"
#include "bp/BpService.h"

#define TAG "NativeImGui"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// 设为 1 可记录触摸坐标与面板矩形的对比，
// 用于在真机上调试对齐 / 拦截问题。
#define TOUCH_DEBUG 0
#if TOUCH_DEBUG
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#else
#define LOGD(...) ((void)0)
#endif

// ── 输入队列——线程安全桥：Java UI 线程 → native 渲染线程 ──
namespace {
enum TouchAction { kDown = 0, kMove = 1, kUp = 2 };

struct TouchEvent { int action; float x, y; int pid; };
struct KeyEvent   { int keyCode; int action; int unicode; };

std::mutex               g_InputLock;
std::vector<TouchEvent>  g_TouchQueue;
std::vector<KeyEvent>    g_KeyQueue;
}

static void EnqueueTouch(int action, float x, float y, int pid) {
    std::lock_guard<std::mutex> lk(g_InputLock);
    g_TouchQueue.push_back({action, x, y, pid});
}
static void EnqueueKey(int keyCode, int action, int unicode) {
    std::lock_guard<std::mutex> lk(g_InputLock);
    g_KeyQueue.push_back({keyCode, action, unicode});
}

// ── Android 键码 → ImGui 键 ──
static ImGuiKey MapKey(int code) {
    switch (code) {
        case AKEYCODE_DPAD_LEFT:   return ImGuiKey_LeftArrow;
        case AKEYCODE_DPAD_RIGHT:  return ImGuiKey_RightArrow;
        case AKEYCODE_DPAD_UP:     return ImGuiKey_UpArrow;
        case AKEYCODE_DPAD_DOWN:   return ImGuiKey_DownArrow;
        case AKEYCODE_TAB:         return ImGuiKey_Tab;
        case AKEYCODE_ENTER:       return ImGuiKey_Enter;
        case AKEYCODE_DEL:         return ImGuiKey_Backspace;
        case AKEYCODE_FORWARD_DEL: return ImGuiKey_Delete;
        case AKEYCODE_ESCAPE:      return ImGuiKey_Escape;
        case AKEYCODE_SPACE:       return ImGuiKey_Space;
        case AKEYCODE_PAGE_UP:     return ImGuiKey_PageUp;
        case AKEYCODE_PAGE_DOWN:   return ImGuiKey_PageDown;
        case AKEYCODE_MOVE_HOME:   return ImGuiKey_Home;
        case AKEYCODE_MOVE_END:    return ImGuiKey_End;
        case AKEYCODE_CTRL_LEFT:   return ImGuiKey_LeftCtrl;
        case AKEYCODE_CTRL_RIGHT:  return ImGuiKey_RightCtrl;
        case AKEYCODE_SHIFT_LEFT:  return ImGuiKey_LeftShift;
        case AKEYCODE_SHIFT_RIGHT: return ImGuiKey_RightShift;
        case AKEYCODE_ALT_LEFT:    return ImGuiKey_LeftAlt;
        case AKEYCODE_ALT_RIGHT:   return ImGuiKey_RightAlt;
        case AKEYCODE_A ... AKEYCODE_Z:
            return (ImGuiKey)(ImGuiKey_A + (code - AKEYCODE_A));
        case AKEYCODE_0 ... AKEYCODE_9:
            return (ImGuiKey)(ImGuiKey_0 + (code - AKEYCODE_0));
        case AKEYCODE_F1 ... AKEYCODE_F12:
            return (ImGuiKey)(ImGuiKey_F1 + (code - AKEYCODE_F1));
        default: return ImGuiKey_None;
    }
}

// ── 渲染状态——由 native 线程持有 ──
static std::thread          g_RenderThread;
static std::atomic<bool>    g_Running{false};
static std::mutex           g_StateMutex;

static ANativeWindow*       g_PendingWindow = nullptr;
static std::atomic<int>     g_SurfaceW{0};
static std::atomic<int>     g_SurfaceH{0};
static std::mutex           g_SurfaceLock;

// 悬浮窗口的屏幕位置 / 尺寸（屏幕像素），
// 由 Java 通过 nativeSetSurfaceOrigin() 上报。用于在屏幕
// 坐标（MotionEvent.rawX/rawY）与 ImGui / Surface 坐标系之间转换。
static std::atomic<float>   g_SurfaceOriginX{0.0f};
static std::atomic<float>   g_SurfaceOriginY{0.0f};
static std::atomic<float>   g_ViewW{0.0f};  // 0 = 尚未上报 -> 按 1:1 缩放
static std::atomic<float>   g_ViewH{0.0f};
static std::atomic<float>   g_ScreenW{0.0f}; // 物理屏幕尺寸（来自 Java）
static std::atomic<float>   g_ScreenH{0.0f};

// 注入信息（由 Java 设置）：独立注入器可执行文件
//（从 assets 解压）和 APK 中打包的 agent .so 的路径。
static std::mutex  g_inject_mutex;
static std::string g_injector_path;
static std::string g_agent_path;
static std::string g_config_dir;   // App 私有 files 目录（配置文件存放处）

// 配置文件路径（App 私有 files 目录，免 root）。
std::string GetConfigFilePath() {
    return g_config_dir.empty()
               ? ""
               : g_config_dir + "/universal_debug_tool.conf";
}

// 返回解压后的注入器路径（断点服务使用）。
std::string GetInjectorPath() {
    std::lock_guard<std::mutex> lk(g_inject_mutex);
    return g_injector_path;
}

// 回传给 Java 的状态（原子量 → 可从任意线程读取）
static std::atomic<bool>    g_WantKeyboard{false};
static std::atomic<bool>    g_WantCaptureMouse{false};

// 音量键开关（输入写入，渲染循环读取）
static std::atomic<int>     g_VolumeClicks{0};

// IsPointInImGuiWindow() 使用的全局指针——被 aimgui_platform 引用
aimgui::UiState* g_UiState = nullptr;

// 弹窗模式：悬浮 Surface 临时扩大（锚定在
// 面板左上角），使弹窗可以拖出主窗口。
static std::atomic<bool> g_overlay_expanded{false};

// 面板（而非悬浮窗口）的屏幕位置。弹窗
// 打开时窗口扩大到全屏，但面板仍在该位置渲染，
// 主窗口保持原位且仍可拖动。
static std::atomic<float> g_panel_x{0.0f};
static std::atomic<float> g_panel_y{0.0f};

namespace aimgui {
void SetOverlayExpanded(bool expanded) {
    g_overlay_expanded.store(expanded);
}
bool IsOverlayExpanded() {
    return g_overlay_expanded.load();
}
void GetPanelOrigin(float& x, float& y) {
    // ImGui 坐标 ==（屏幕 - 窗口原点）；面板位置
    // 以屏幕坐标上报，因此相对窗口转换。
    x = g_panel_x.load() - g_SurfaceOriginX.load();
    y = g_panel_y.load() - g_SurfaceOriginY.load();
}
} // 命名空间 aimgui

// ── 坐标转换 ──
//
// MotionEvent 提供屏幕坐标。ImGui 绘制在 Surface 缓冲
// 坐标系（io.DisplaySize = Surface 尺寸）。两个坐标系
// 通过悬浮窗口的屏幕位置和尺寸关联：
//
//   imgui = (screen - origin) * (surfaceW / viewW)
//
static void GetSurfaceScales(float& scaleX, float& scaleY) {
    float vw = g_ViewW.load();
    float vh = g_ViewH.load();
    scaleX = (vw > 0.0f) ? (float)g_SurfaceW.load() / vw : 1.0f;
    scaleY = (vh > 0.0f) ? (float)g_SurfaceH.load() / vh : 1.0f;
}

static float ScreenToImGuiX(float sx) {
    float sxScale, syScale;
    GetSurfaceScales(sxScale, syScale);
    return (sx - g_SurfaceOriginX.load()) * sxScale;
}

static float ScreenToImGuiY(float sy) {
    float sxScale, syScale;
    GetSurfaceScales(sxScale, syScale);
    return (sy - g_SurfaceOriginY.load()) * syScale;
}

static float ImGuiToScreenX(float ix) {
    float sxScale, syScale;
    GetSurfaceScales(sxScale, syScale);
    return ix / sxScale + g_SurfaceOriginX.load();
}

static float ImGuiToScreenY(float iy) {
    float sxScale, syScale;
    GetSurfaceScales(sxScale, syScale);
    return iy / syScale + g_SurfaceOriginY.load();
}

// ── ComputePanelRect——imgui 窗口矩形（Surface / 屏幕坐标）──
// imgui 窗口锚定在 (0,0) 并铺满整个 Surface。
static void ComputePanelRect(float& out_x, float& out_y,
                             float& out_w, float& out_h) {
    if (!g_UiState) {
        out_x = out_y = out_w = out_h = 0.0f;
        return;
    }
    out_x = 0.0f;
    out_y = 0.0f;
    out_w = (float)g_SurfaceW.load();
    out_h = (float)g_SurfaceH.load();
}

// ── IsPointInImGuiWindow——几何命中测试（屏幕坐标）──
// 单窗口悬浮层下，投递给窗口的每个触摸
// 都在面板内；这里保留作健全性检查。
bool IsPointInImGuiWindow(float sx, float sy) {
    if (!g_UiState) return false;
    if (g_UiState->exit_anim_active) return true;

    float x = ScreenToImGuiX(sx);
    float y = ScreenToImGuiY(sy);

    float px, py, pw, ph;
    ComputePanelRect(px, py, pw, ph);

    const float pad = 15.0f;
    bool hit = (x >= px - pad && x <= px + pw + pad &&
                y >= py - pad && y <= py + ph + pad);

    LOGD("hit: screen=(%.0f,%.0f) imgui=(%.0f,%.0f) panel=(%.0f,%.0f,%.0f,%.0f) => %d",
         sx, sy, x, y, px, py, pw, ph, hit ? 1 : 0);
    return hit;
}

// ── 输入处理——渲染线程每帧调用一次 ──
static void ProcessInput(ImGuiIO& io) {
    std::lock_guard<std::mutex> lk(g_InputLock);

    for (auto& ke : g_KeyQueue) {
        if (ke.action == 1) { // 按键抬起
            if (ke.keyCode == AKEYCODE_VOLUME_UP || ke.keyCode == AKEYCODE_VOLUME_DOWN)
                g_VolumeClicks.fetch_add(1);
        }
        ImGuiKey ik = MapKey(ke.keyCode);
        if (ik != ImGuiKey_None)
            io.AddKeyEvent(ik, ke.action == 0);
        if (ke.unicode > 0 && ke.action == 0)
            io.AddInputCharacter((unsigned int)ke.unicode);
    }

    for (auto& te : g_TouchQueue) {
        float ix = ScreenToImGuiX(te.x);
        float iy = ScreenToImGuiY(te.y);
        LOGD("touch: action=%d screen=(%.0f,%.0f) imgui=(%.0f,%.0f)",
             te.action, te.x, te.y, ix, iy);
        io.AddMousePosEvent(ix, iy);
        if (te.action == kDown)
            io.AddMouseButtonEvent(0, true);
        else if (te.action == kUp)
            io.AddMouseButtonEvent(0, false);
    }

    g_TouchQueue.clear();
    g_KeyQueue.clear();
}

// ── 渲染循环——运行在专用线程，持有 EGL 上下文 ──
static void RenderLoop() {
    using clock = std::chrono::steady_clock;

    // ── 等待 Surface ──
    ANativeWindow* window = nullptr;
    int w = 0, h = 0;
    {
        // 最多等待 2 秒让 Surface 到达
        for (int i = 0; i < 40 && !g_PendingWindow; ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::lock_guard<std::mutex> lk(g_SurfaceLock);
        window = g_PendingWindow;
        w = g_SurfaceW.load();
        h = g_SurfaceH.load();
    }
    if (!window) {
        LOGE("No surface – aborting render thread");
        g_Running = false;
        return;
    }

    LOGI("Got surface %dx%d – creating ImGui + renderer", w, h);

    auto InitImGuiIO = [] {
        ImGuiIO& io = ImGui::GetIO();
        io.IniFilename = nullptr;
        io.LogFilename = nullptr;
        io.ConfigFlags |= ImGuiConfigFlags_NoMouseCursorChange;
        io.ConfigErrorRecoveryEnableAssert = false;
        ImGui::StyleColorsDark();
    };

    auto createRenderer = [window](int rw, int rh) {
        auto r = aimgui::MakeRenderer(window, rw, rh, aimgui::Backend::OpenGL);
        if (!r) {
            LOGE("MakeRenderer failed – no backend available");
            return std::unique_ptr<aimgui::IRenderer>{};
        }
        LOGI("Renderer: %s", r->Name());
        // 字体需要当前 GL 上下文
        aimgui::LoadDefaultAndSystemCJKFont(25.0f);
        return r;
    };

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    InitImGuiIO();

    auto renderer = createRenderer(w, h);
    if (!renderer) {
        ImGui::DestroyContext();
        ANativeWindow_release(window);
        g_PendingWindow = nullptr;
        g_Running = false;
        return;
    }

    aimgui::UiState st{};
    st.display_w = w;
    st.display_h = h;
    g_UiState = &st;

    aimgui::FramePacer pacer;
    auto last = clock::now();
    bool running = true;

    LOGI("=== Render loop starting ===");

    while (running && g_Running.load()) {
        ImGuiIO& io = ImGui::GetIO();

        // Surface 尺寸变化时重建渲染器（收起、
        // 缩放、旋转），使 io.DisplaySize 始终与缓冲匹配。
        int curW = g_SurfaceW.load();
        int curH = g_SurfaceH.load();
        if (curW > 0 && curH > 0 && (curW != w || curH != h)) {
            LOGI("Surface resized %dx%d -> %dx%d; recreating renderer",
                 w, h, curW, curH);
            if (renderer) {
                renderer->Shutdown();
                renderer.reset();
            }
            ImGui::DestroyContext();
            ImGui::CreateContext();
            InitImGuiIO();
            renderer = createRenderer(curW, curH);
            if (renderer) {
                w = curW;
                h = curH;
                st.display_w = w;
                st.display_h = h;
                last = clock::now();
                continue;
            }
            // Surface 可能正在缩放中；在后续帧重试，
            // 而不是销毁整个 GUI。
            LOGI("renderer recreate failed (%dx%d), will retry", curW, curH);
            std::this_thread::sleep_for(std::chrono::milliseconds(80));
            continue;
        }
        if (!renderer) {
            std::this_thread::sleep_for(std::chrono::milliseconds(80));
            continue;
        }

        auto now = clock::now();
        io.DeltaTime = std::max(1e-6f,
            std::chrono::duration<float>(now - last).count());
        last = now;

        pacer.SetTargetFps(st.target_fps);

        ProcessInput(io);

        // 音量键收起开关
        if (g_VolumeClicks.exchange(0) > 0)
            st.collapsed = !st.collapsed;

        renderer->NewFrame();
        st.scene_snapshot_id = renderer->GetSceneSnapshotID();
        ImGui::NewFrame();
        aimgui::DrawUi(&st, &running);
        renderer->SetBloomIntensity(st.bloom_intensity);
        renderer->SetSnapshotFrozen(st.exit_anim_active);
        ImGui::Render();
        renderer->EndFrame();

        // 回传给 Java
        g_WantKeyboard.store(io.WantTextInput);
        g_WantCaptureMouse.store(io.WantCaptureMouse);

        pacer.Wait();
    }

    LOGI("=== Render loop exiting ===");

    if (renderer) renderer->Shutdown();
    ImGui::DestroyContext();
    g_UiState = nullptr;

    if (window) {
        ANativeWindow_release(window);
        g_PendingWindow = nullptr;
    }

    g_Running = false;
}

// ── 注入（ptrace）──
// 在 `su` 下为指定包运行独立注入器可执行文件
// 并返回捕获的输出。必须在后台线程调用：
// `su` + ptrace 注入可能耗时，
// 绝不能阻塞渲染线程。
static std::string RunInjectorArgs(const std::string& args) {
    std::string inj, agent;
    {
        std::lock_guard<std::mutex> lk(g_inject_mutex);
        inj = g_injector_path;
        agent = g_agent_path;
    }
    if (inj.empty() || agent.empty())
        return "错误: injector/agent 路径未设置";

    // 被注入的 agent 以目标应用的 uid 运行，必须能
    // 在 /data/local/tmp 下创建密钥文件和 unix socket。
    // 先用 root 开放目录权限；对已允许的设备无害。
    {
        FILE* prep = popen("su -c 'chmod 777 /data/local/tmp' 2>&1 </dev/null", "r");
        if (prep) pclose(prep);
    }

    std::string cmd = "su -c '" + inj + " " + args + " -l " + agent + "' 2>&1";
    FILE* f = popen(cmd.c_str(), "r");
    if (!f) return "错误: 无法启动 su";

    std::string out;
    char buf[1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        out.append(buf, n);
    int rc = pclose(f);

    // 如果注入器没有任何输出（例如在打日志前崩溃），
    // 显示退出码，避免 UI 静默无提示。
    if (out.empty() && rc != 0) {
        out = "injector 无输出，退出码 " + std::to_string(rc);
    }

    if (out.size() > 2048)
        out = out.substr(out.size() - 2048);
    return out;
}

std::string RunInjector(const std::string& pkg) {
    return RunInjectorArgs("-p " + pkg);
}

// 按 PID 注入：用于 native ELF 等非应用进程——没有包名可解析，
// 注入器把 agent 复制到 /data/local/tmp 供目标读取。
std::string RunInjectorPid(int pid) {
    return RunInjectorArgs("-i " + std::to_string(pid));
}

// ── Root 内存辅助函数（imgui 内存查看器使用）──
// 在 `su` 下运行命令并返回捕获的输出。cmd 不能
// 包含单引号。
std::string RunSuCommand(const std::string& cmd) {
    std::string full = "su -c '" + cmd + "' 2>&1 </dev/null";
    FILE* f = popen(full.c_str(), "r");
    if (!f) return "";
    std::string out;
    char buf[1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        out.append(buf, n);
    pclose(f);
    return out;
}

std::string ReadRemoteMaps(int pid) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "cat /proc/%d/maps", pid);
    return RunSuCommand(cmd);
}

bool ReadRemoteDword(int pid, uintptr_t addr, uint32_t& out) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "dd if=/proc/%d/mem bs=1 skip=%llu count=4 2>/dev/null | xxd -p -c 8",
        pid, (unsigned long long)addr);
    std::string hex = RunSuCommand(cmd);
    // xxd -p 按文件顺序打印字节，例如 "78563412\n"
    if (hex.size() < 8) return false;
    uint32_t v = 0;
    for (int i = 0; i < 8; ++i) {
        char c = hex[i];
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return false;
        v = (v << 4) | (uint32_t)d;
    }
    out = v;
    return true;
}

bool ReadRemoteBytes(int pid, uintptr_t addr, void* buf, size_t n) {
    char cmd[320];
    snprintf(cmd, sizeof(cmd),
        "dd if=/proc/%d/mem bs=1 skip=%llu count=%zu 2>/dev/null | xxd -p",
        pid, (unsigned long long)addr, n);
    std::string hex = RunSuCommand(cmd);
    unsigned char* out = static_cast<unsigned char*>(buf);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    size_t got = 0;
    int hi = -1;
    for (size_t i = 0; i < hex.size() && got < n; ++i) {
        int d = nib(hex[i]);
        if (d < 0) continue;  // 跳过换行 / 空白
        if (hi < 0) {
            hi = d;
        } else {
            out[got++] = (unsigned char)((hi << 4) | d);
            hi = -1;
        }
    }
    return got > 0;
}

// 内存搜索用的快速页对齐批量读取。addr 必须 4096 对齐，
// n 是 4096 的倍数；用块大小 dd 读取，完整扫描
// 比每字节一次 bs=1 调用快几个数量级。
bool ReadRemoteChunk(int pid, uintptr_t addr, void* buf, size_t n) {
    size_t pages = n / 4096;
    if (pages == 0 || (addr & 4095) != 0) return false;
    char cmd[320];
    snprintf(cmd, sizeof(cmd),
        "dd if=/proc/%d/mem bs=4096 skip=%llu count=%zu 2>/dev/null | xxd -p",
        pid, (unsigned long long)(addr / 4096), pages);
    std::string hex = RunSuCommand(cmd);
    unsigned char* out = static_cast<unsigned char*>(buf);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    size_t got = 0;
    int hi = -1;
    for (size_t i = 0; i < hex.size() && got < n; ++i) {
        int d = nib(hex[i]);
        if (d < 0) continue;
        if (hi < 0) {
            hi = d;
        } else {
            out[got++] = (unsigned char)((hi << 4) | d);
            hi = -1;
        }
    }
    return got > 0;
}

// 搜索改善用的批量页读取器：通过一次 su 调用
//（内部批量）读取远程进程的指定 4KB 页，而不是
// 每个 8MB 块一次 su + dd + xxd 往返。每页恰好输出 4096
// 字节（页面读取失败时输出 0），因此输出可以确定性地切分。
// 仅当整批数据丢失时才返回 false。
bool ReadRemotePages(int pid, const std::vector<uintptr_t>& pages,
                     std::vector<uint8_t>& out) {
    out.clear();
    if (pages.empty()) return true;

    constexpr size_t kBatch = 400;
    const size_t total = pages.size();
    out.resize(total * 4096);

    for (size_t base = 0; base < total; base += kBatch) {
        const size_t cnt = std::min(kBatch, total - base);
        std::string cmd = "for o in";
        for (size_t i = 0; i < cnt; ++i) {
            char num[24];
            snprintf(num, sizeof(num), " %llu",
                     (unsigned long long)(pages[base + i] / 4096));
            cmd += num;
        }
        char pbuf[16];
        snprintf(pbuf, sizeof(pbuf), "%d", pid);
        cmd += "; do dd if=/proc/";
        cmd += pbuf;
        cmd += "/mem bs=4096 skip=$o count=1 2>/dev/null || "
               "dd if=/dev/zero bs=4096 count=1 2>/dev/null; done";

        std::string raw = RunSuCommand(cmd);
        const size_t need = cnt * 4096;
        if (raw.size() < need) return false;
        memcpy(out.data() + base * 4096, raw.data(), need);
    }
    return true;
}

bool WriteRemoteDword(int pid, uintptr_t addr, uint32_t value) {
    unsigned char b0 = (unsigned char)(value & 0xff);
    unsigned char b1 = (unsigned char)((value >> 8) & 0xff);
    unsigned char b2 = (unsigned char)((value >> 16) & 0xff);
    unsigned char b3 = (unsigned char)((value >> 24) & 0xff);
    char cmd[320];
    snprintf(cmd, sizeof(cmd),
        "printf \"\\x%02x\\x%02x\\x%02x\\x%02x\" | dd of=/proc/%d/mem bs=1 seek=%llu conv=notrunc 2>&1",
        b0, b1, b2, b3, pid, (unsigned long long)addr);
    std::string out = RunSuCommand(cmd);
    // dd 成功时打印 "N+0 records in"。
    return out.find("records in") != std::string::npos;
}

// ── JNI 辅助：系统剪贴板（imgui 内存编辑器使用）──
static JavaVM* g_jvm = nullptr;
static jobject g_activity_ref = nullptr;

// 通过保存的 Activity 把 ASCII 文本复制到 Android 剪贴板。
// 可从任意线程安全调用（必要时附加到 VM）。
bool CopyToClipboard(const std::string& text) {
    if (!g_jvm || !g_activity_ref) {
        LOGE("CopyToClipboard: no jvm(%p)/activity(%p)", (void*)g_jvm,
             (void*)g_activity_ref);
        return false;
    }

    JNIEnv* env = nullptr;
    bool attached = false;
    if (g_jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        if (g_jvm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
            LOGE("CopyToClipboard: attach failed");
            return false;
        }
        attached = true;
    }

    bool ok = false;
    jclass ctxCls = env->FindClass("android/content/Context");
    jclass actCls = env->GetObjectClass(g_activity_ref);
    if (!ctxCls || !actCls) {
        LOGE("CopyToClipboard: class lookup failed (ctx=%p act=%p)",
             (void*)ctxCls, (void*)actCls);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (actCls) env->DeleteLocalRef(actCls);
        if (attached) g_jvm->DetachCurrentThread();
        return false;
    }
    if (ctxCls && actCls) {
        jmethodID getSys = env->GetMethodID(
            actCls, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;");
        jfieldID svcFld = env->GetStaticFieldID(
            ctxCls, "CLIPBOARD_SERVICE", "Ljava/lang/String;");
        if (getSys && svcFld) {
            jobject svc = env->CallObjectMethod(
                g_activity_ref, getSys,
                env->GetStaticObjectField(ctxCls, svcFld));
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
                LOGE("CopyToClipboard: getSystemService threw");
            }
            if (svc) {
                jclass cmCls = env->GetObjectClass(svc);
                jmethodID setPrimary = env->GetMethodID(
                    cmCls, "setPrimaryClip",
                    "(Landroid/content/ClipData;)V");
                jclass clipDataCls = env->FindClass("android/content/ClipData");
                jmethodID newPlainText = env->GetStaticMethodID(
                    clipDataCls, "newPlainText",
                    "(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)"
                    "Landroid/content/ClipData;");
                jstring jstr = env->NewStringUTF(text.c_str());
                jstring jlabel = env->NewStringUTF("udt");
                jobject clip = newPlainText && jstr && jlabel
                    ? env->CallStaticObjectMethod(clipDataCls, newPlainText,
                                                  jlabel, jstr)
                    : nullptr;
                if (setPrimary && clip) {
                    env->CallVoidMethod(svc, setPrimary, clip);
                    ok = !env->ExceptionCheck();
                    if (env->ExceptionCheck()) {
                        env->ExceptionClear();
                        LOGE("CopyToClipboard: setPrimaryClip threw");
                    }
                } else {
                    LOGE("CopyToClipboard: setPrimaryClip/clip missing");
                }

                // 读回剪贴板以验证写入确实生效。
                jmethodID hasPrimary = env->GetMethodID(
                    cmCls, "hasPrimaryClip", "()Z");
                jmethodID getPrimary = env->GetMethodID(
                    cmCls, "getPrimaryClip",
                    "()Landroid/content/ClipData;");
                jstring back = nullptr;
                if (hasPrimary && getPrimary) {
                    jboolean has = env->CallBooleanMethod(svc, hasPrimary);
                    jobject pc = env->CallObjectMethod(svc, getPrimary);
                    if (has && pc) {
                        jclass pcCls = env->GetObjectClass(pc);
                        jmethodID getItem = env->GetMethodID(
                            pcCls, "getItemAt",
                            "(I)Landroid/content/ClipData$Item;");
                        jobject item = getItem
                            ? env->CallObjectMethod(pc, getItem, 0) : nullptr;
                        if (item) {
                            jclass itemCls = env->GetObjectClass(item);
                            jmethodID getText = env->GetMethodID(
                                itemCls, "getText",
                                "()Ljava/lang/CharSequence;");
                            if (getText) {
                                jobject cs = env->CallObjectMethod(item, getText);
                                back = cs ? (jstring)cs : nullptr;
                            }
                            env->DeleteLocalRef(item);
                        }
                        env->DeleteLocalRef(pc);
                    }
                }
                if (back) {
                    const char* utf = env->GetStringUTFChars(back, nullptr);
                    LOGI("CopyToClipboard: write=%s readback=\"%s\"",
                         ok ? "ok" : "failed",
                         utf ? utf : "(null)");
                    if (utf) env->ReleaseStringUTFChars(back, utf);
                    env->DeleteLocalRef(back);
                } else {
                    LOGI("CopyToClipboard: write=%s readback=(empty)",
                         ok ? "ok" : "failed");
                }
                if (jstr) env->DeleteLocalRef(jstr);
                if (jlabel) env->DeleteLocalRef(jlabel);
                if (clip) env->DeleteLocalRef(clip);
                if (clipDataCls) env->DeleteLocalRef(clipDataCls);
                env->DeleteLocalRef(svc);
            } else {
                LOGE("CopyToClipboard: clipboard service is null");
            }
        } else {
            LOGE("CopyToClipboard: getSystemService/CLIPBOARD_SERVICE lookup failed");
        }
        env->DeleteLocalRef(actCls);
    }
    if (ctxCls) env->DeleteLocalRef(ctxCls);

    if (attached) g_jvm->DetachCurrentThread();
    return ok;
}

extern "C" {

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
    g_jvm = vm;
    return JNI_VERSION_1_6;
}

// ── JNI——Surface 生命周期（由 Java UI 线程调用）──

JNIEXPORT void JNICALL
Java_com_Alive_Trace_MainActivity_nativeSurfaceCreated(
    JNIEnv* env, jobject /*this*/, jobject surface, jint width, jint height) {

    std::lock_guard<std::mutex> lk(g_SurfaceLock);

    if (g_PendingWindow) {
        ANativeWindow_release(g_PendingWindow);
        g_PendingWindow = nullptr;
    }

    g_PendingWindow = ANativeWindow_fromSurface(env, surface);
    g_SurfaceW.store(width);
    g_SurfaceH.store(height);

    if (g_PendingWindow)
        LOGI("Surface acquired: %dx%d", width, height);
    else
        LOGE("Failed to acquire ANativeWindow from Surface");
}

JNIEXPORT void JNICALL
Java_com_Alive_Trace_MainActivity_nativeSurfaceChanged(
    JNIEnv*, jobject, jint w, jint h) {
    g_SurfaceW.store(w);
    g_SurfaceH.store(h);
}

JNIEXPORT void JNICALL
Java_com_Alive_Trace_MainActivity_nativeSurfaceDestroyed(
    JNIEnv*, jobject) {

    if (g_Running.load()) {
        g_Running = false;
    }
    LOGI("Surface destroyed");
}

// ── 渲染线程控制 ──

JNIEXPORT void JNICALL
Java_com_Alive_Trace_MainActivity_nativeStartRender(
    JNIEnv* env, jobject thiz) {

    std::lock_guard<std::mutex> lk(g_StateMutex);

    if (!g_activity_ref)
        g_activity_ref = env->NewGlobalRef(thiz);

    if (g_Running.load()) {
        LOGI("Render already running");
        return;
    }

    g_Running = true;

    JavaVM* vm = nullptr;
    env->GetJavaVM(&vm);

    g_RenderThread = std::thread([vm] {
        JNIEnv* threadEnv = nullptr;
        bool attached = false;
        if (vm->GetEnv((void**)&threadEnv, JNI_VERSION_1_6) != JNI_OK) {
            if (vm->AttachCurrentThread(&threadEnv, nullptr) == JNI_OK)
                attached = true;
        }
        RenderLoop();
        if (attached)
            vm->DetachCurrentThread();
    });

    LOGI("Render thread launched");
}

JNIEXPORT void JNICALL
Java_com_Alive_Trace_MainActivity_nativeStopRender(
    JNIEnv*, jobject) {

    std::lock_guard<std::mutex> lk(g_StateMutex);

    // 与悬浮层一起释放 SO 通道，使下一次会话
    // 从干净、未连接的状态开始。
    g_socket.Disconnect();
    // 同时释放 root 硬件断点服务（否则悬浮层隐藏后
    // 它仍会继续监视目标进程）。
    g_bp.Stop();

    g_Running = false;
    if (g_RenderThread.joinable())
        g_RenderThread.join();

    LOGI("Render thread joined");
}

// ── 输入（由 Java UI 线程调用）──

JNIEXPORT void JNICALL
Java_com_Alive_Trace_MainActivity_nativeTouchEvent(
    JNIEnv*, jobject, jint action, jfloat x, jfloat y, jint pid) {
    EnqueueTouch(action, x, y, pid);
}

JNIEXPORT void JNICALL
Java_com_Alive_Trace_MainActivity_nativeKeyEvent(
    JNIEnv*, jobject, jint keyCode, jint action, jint unicode) {
    EnqueueKey(keyCode, action, unicode);
}

// ── 悬浮窗口原点 / 缩放（由 Java UI 线程调用）──
JNIEXPORT void JNICALL
Java_com_Alive_Trace_MainActivity_nativeSetSurfaceOrigin(
    JNIEnv*, jobject, jfloat x, jfloat y, jfloat viewW, jfloat viewH,
    jfloat screenW, jfloat screenH) {
    g_SurfaceOriginX.store(x);
    g_SurfaceOriginY.store(y);
    g_ViewW.store(viewW > 0.0f ? viewW : 0.0f);
    g_ViewH.store(viewH > 0.0f ? viewH : 0.0f);
    g_ScreenW.store(screenW > 0.0f ? screenW : 0.0f);
    g_ScreenH.store(screenH > 0.0f ? screenH : 0.0f);
}

// 面板的屏幕位置（与窗口原点分开跟踪，
// 这样弹窗保持窗口全屏时主窗口仍可拖动）
// 。
JNIEXPORT void JNICALL
Java_com_Alive_Trace_MainActivity_nativeSetPanelOrigin(
    JNIEnv*, jobject, jfloat x, jfloat y) {
    g_panel_x.store(x);
    g_panel_y.store(y);
}

// 注入路径（从 assets 解压的注入器可执行文件 + APK 中
// 打包的 agent .so）。
JNIEXPORT void JNICALL
Java_com_Alive_Trace_MainActivity_nativeSetInjectorInfo(
    JNIEnv* env, jobject, jstring injectorPath, jstring agentPath) {
    const char* ip = injectorPath ? env->GetStringUTFChars(injectorPath, nullptr) : nullptr;
    const char* ap = agentPath ? env->GetStringUTFChars(agentPath, nullptr) : nullptr;
    {
        std::lock_guard<std::mutex> lk(g_inject_mutex);
        g_injector_path = ip ? ip : "";
        g_agent_path = ap ? ap : "";
    }
    if (ip) env->ReleaseStringUTFChars(injectorPath, ip);
    if (ap) env->ReleaseStringUTFChars(agentPath, ap);
}

// 配置文件目录（App 私有 files 目录，由 Java 传入）。
JNIEXPORT void JNICALL
Java_com_Alive_Trace_MainActivity_nativeSetConfigDir(
    JNIEnv* env, jobject, jstring dir) {
    const char* d = dir ? env->GetStringUTFChars(dir, nullptr) : nullptr;
    g_config_dir = d ? d : "";
    if (d) env->ReleaseStringUTFChars(dir, d);
}

// ── 状态查询（任意线程调用，无锁）──

JNIEXPORT jboolean JNICALL
Java_com_Alive_Trace_MainActivity_nativeWantKeyboard(
    JNIEnv*, jobject) {
    return g_WantKeyboard.load() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_Alive_Trace_MainActivity_nativeWantCaptureMouse(
    JNIEnv*, jobject) {
    return g_WantCaptureMouse.load() ? JNI_TRUE : JNI_FALSE;
}

// 返回面板窗口在屏幕坐标下的目标边界。应用把
// 单个悬浮窗口的位置 / 尺寸精确设置为该矩形。
JNIEXPORT void JNICALL
Java_com_Alive_Trace_MainActivity_nativeGetPanelRect(
    JNIEnv* env, jobject, jfloatArray rect) {
    jfloat* arr = env->GetFloatArrayElements(rect, nullptr);
    if (!arr) return;

    if (!g_UiState) {
        arr[0] = arr[1] = arr[2] = arr[3] = 0.0f;
    } else if (g_UiState->collapsed) {
        // 收起状态：应用把悬浮窗口缩小为 280x56 的胶囊。
        // Java 用 CENTER_HORIZONTAL 重力使其居中，因此这里的
        // 位置只是兜底（应用的显示指标在旋转后可能过期，
        // 所以我们从不自行计算居中）。
        arr[0] = 0.0f;
        arr[1] = 28.0f;
        arr[2] = 280.0f;
        arr[3] = 56.0f;
    } else if (g_overlay_expanded.load()) {
        // 弹窗模式：窗口从面板左上角扩大到
        // 屏幕右下角，使弹窗可以拖出
        // 主窗口。窗口原点不动，因此 GetPanelOrigin
        // 保持 0，主窗口继续铺满面板。
        //
        // 注意：保持适度扩大。过大的请求尺寸会让
        // 部分 ROM 分配超大 Surface 缓冲并卡死 / 杀死
        // 应用，因此这里绝不要返回 20000 之类的值。
        float sx = g_panel_x.load();
        float sy = g_panel_y.load();
        float screenW = g_ScreenW.load();
        float screenH = g_ScreenH.load();
        if (screenW <= 0.0f) screenW = (float)g_SurfaceW.load();
        if (screenH <= 0.0f) screenH = (float)g_SurfaceH.load();
        float w = screenW - sx;
        float h = screenH - sy;
        if (w < 200.0f) w = screenW;
        if (h < 200.0f) h = screenH;
        arr[0] = sx;
        arr[1] = sy;
        arr[2] = w;
        arr[3] = h;
    } else {
        // 普通状态：窗口就是面板；上报其位置 + 尺寸。
        arr[0] = g_panel_x.load();
        arr[1] = g_panel_y.load();
        arr[2] = g_UiState->last_full_size.x;
        arr[3] = g_UiState->last_full_size.y;
    }

    env->ReleaseFloatArrayElements(rect, arr, 0);
}

JNIEXPORT jboolean JNICALL
Java_com_Alive_Trace_MainActivity_nativeIsPointInWindow(
    JNIEnv*, jobject, jfloat x, jfloat y) {
    return IsPointInImGuiWindow(x, y) ? JNI_TRUE : JNI_FALSE;
}

// 当点在窗口标题栏上（拖动会移动整个
// 悬浮窗口）或窗口已收起（整个胶囊可拖动）时返回 true。
JNIEXPORT jboolean JNICALL
Java_com_Alive_Trace_MainActivity_nativeIsOnTitleBar(
    JNIEnv*, jobject, jfloat x, jfloat y) {
    if (!g_UiState) return JNI_FALSE;
    // 收起时胶囊必须不可拖动：移动窗口会
    // 把巨大的离屏 Surface 拉到屏幕上并拦截触摸。
    if (g_UiState->collapsed) return JNI_FALSE;
    // 按屏幕坐标对面板矩形做命中测试（窗口可能是
    // 全屏的，因此简单的窗口矩形检查
    // 会出错）。
    float px = g_panel_x.load();
    float py = g_panel_y.load();
    float pw = g_UiState->last_full_size.x;
    bool hit = (x >= px && x < px + pw && y >= py && y <= py + 52.0f);
    return hit ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_Alive_Trace_MainActivity_nativeIsCollapsed(
    JNIEnv*, jobject) {
    return (g_UiState && g_UiState->collapsed) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_Alive_Trace_MainActivity_nativeIsOverlayExpanded(
    JNIEnv*, jobject) {
    return g_overlay_expanded.load() ? JNI_TRUE : JNI_FALSE;
}

// 展开面板（收起胶囊被点击时由 Java 直接调用，
// 这样展开不依赖 ImGui 的悬停 / 点击检测，
// 也不依赖坐标映射的精确性）。
JNIEXPORT void JNICALL
Java_com_Alive_Trace_MainActivity_nativeExpand(
    JNIEnv*, jobject) {
    if (g_UiState) {
        g_UiState->collapsed = false;
    }
}

JNIEXPORT jboolean JNICALL
Java_com_Alive_Trace_MainActivity_nativeIsRunning(
    JNIEnv*, jobject) {
    return g_Running.load() ? JNI_TRUE : JNI_FALSE;
}

} // extern "C"
