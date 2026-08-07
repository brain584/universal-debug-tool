// --- START OF FILE main.cpp ---
// AImGui: a minimal Dear ImGui Android ARM64 ELF.
#include "core/font.h"
#include "core/frame_pacer.h"
#include "core/keyboard_input.h"
#include "core/window_session.h"
#include "imgui.h"
#include "platform/ANativeWindowCreator.h"
#include "platform/TouchHelperA.h"
#include "ui/ui.h"
#include <chrono>

// 【新增】全局 UI 状态指针
aimgui::UiState* g_UiState = nullptr;

// 【新增】纯公开 API + 物理数学算法：完美绕过缺少 internal 的问题
bool IsPointInImGuiWindow(float x, float y) {
    // 1. 对于组合框下拉菜单等超越主界面边界的悬浮窗，通过公开API判定拦截
    if (ImGui::GetCurrentContext() && ImGui::GetIO().WantCaptureMouse) {
        return true;
    }
    
    // 2. 0帧延迟数学边界计算拦截（解决第一下按压漏透的情况）
    if (!g_UiState) return false;
    if (g_UiState->exit_anim_active) return true; // 退出动画期间阻断一切背后触摸

    float lt = g_UiState->expand; // 0.0 到 1.0 之间的动画插值
    
    // 这里还原 ui.cpp 里的排版数学逻辑
    float kIslandW = 280.0f;
    float kIslandH = 56.0f;
    float kIslandTop = 28.0f;
    float dw = g_UiState->display_w;
    
    float ix = dw * 0.5f - kIslandW * 0.5f;
    float iy = kIslandTop;
    
    // 实时推算当前 UI 的精确物理坐标和大小（无论是折叠还是展开状态）
    float wx = ix + (g_UiState->last_full_pos.x - ix) * lt;
    float wy = iy + (g_UiState->last_full_pos.y - iy) * lt;
    float ww = kIslandW + (g_UiState->last_full_size.x - kIslandW) * lt;
    float wh = kIslandH + (g_UiState->last_full_size.y - kIslandH) * lt;
    
    float pad = 15.0f; // 手指吸附缓冲区域（防止按在边缘滑出）
    if (x >= wx - pad && x <= wx + ww + pad && 
        y >= wy - pad && y <= wy + wh + pad) {
        return true;
    }
    return false;
}

int main() {
    using namespace android;
    using clock = std::chrono::steady_clock;

    auto info = ANativeWindowCreator::GetDisplayInfo();
    const int W = info.width > info.height ? info.width : info.height;
    const int H = info.width > info.height ? info.height : info.width;

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    auto& io = ImGui::GetIO();
    io.IniFilename = nullptr; io.LogFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_NoMouseCursorChange;
    io.ConfigErrorRecoveryEnableAssert = false;
    ImGui::StyleColorsDark();
    aimgui::LoadDefaultAndSystemCJKFont(25.0f);

    aimgui::UiState st;
    st.display_w = info.width; st.display_h = info.height;
    g_UiState = &st; // 【新增】绑定全局指针提供给触控模块运算

    aimgui::WindowSession ws;
    if (!ws.Build(W, st.permeate_record)) { ImGui::DestroyContext(); return 1; }
    st.renderer_name = ws.renderer()->Name();
    
    // 【关键修复】确保此处为 false 以启用设备的独占读取模式 (uinput转发)
    Touch::Init({(float)W, (float)H}, false);
    Touch::setOrientation((int)info.orientation);
    
    aimgui::kbd_input::Init();

    aimgui::FramePacer pacer;
    auto last = clock::now();
    uint32_t orient = info.orientation;
    bool running = true;
    while (running) {
        auto now = clock::now();
        io.DeltaTime = std::max(1e-6f, std::chrono::duration<float>(now - last).count());
        last = now;
        pacer.SetTargetFps(st.target_fps);
        info = ANativeWindowCreator::GetDisplayInfo();
        st.display_w = info.width; st.display_h = info.height;
        if (info.orientation != orient) { orient = info.orientation; Touch::setOrientation((int)orient); }
        if (aimgui::kbd_input::ConsumeVolumePresses() > 0) st.collapsed = !st.collapsed;
        if (!st.permeate_record) ANativeWindowCreator::ProcessMirrorDisplay();
        aimgui::kbd_input::Flush();

        ws.renderer()->NewFrame();
        st.scene_snapshot_id = ws.renderer()->GetSceneSnapshotID();
        ImGui::NewFrame();
        aimgui::DrawUi(&st, &running);
        ws.renderer()->SetBloomIntensity(st.bloom_intensity);
        ws.renderer()->SetSnapshotFrozen(st.exit_anim_active);
        ws.renderer()->EndFrame();
        pacer.Wait();

        if (st.request_permeate_toggle) {
            st.request_permeate_toggle = false;
            st.permeate_record = !st.permeate_record;
            ws.Destroy();
            if (!ws.Build(W, st.permeate_record)) { running = false; break; }
            st.renderer_name = ws.renderer()->Name();
        }
    }
    aimgui::kbd_input::Shutdown();
    ws.Destroy();
    ImGui::DestroyContext();
}