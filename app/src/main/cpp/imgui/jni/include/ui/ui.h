#pragma once

#include "imgui.h"   // ImVec2 类型

namespace aimgui {

// 主循环与 UI 层之间共享的状态。主循环持有该结构体，
// 每帧把指针传给 DrawUi()；UI 设置 *request_* 标志，
// 主循环在下一帧消费并清除这些标志。
struct UiState {
    const char* renderer_name = nullptr;

    // 帧率上限。0 = 垂直同步（跟随面板刷新）。
    int target_fps = 0;

    // 当前可见显示尺寸（ImGui 坐标系），用于横竖屏旋转时
    // Dynamic Island 重新居中自身。
    int display_w = 0;
    int display_h = 0;

    // ── 灵动岛（Dynamic Island）───────────────────────────────────────────────
    // `collapsed` 是目标状态（true = 顶部胶囊，false = 全窗口）。
    // `expand` 是朝目标状态插值的动画值（弹簧模型），
    // `expand_vel` 是弹簧的速度。
    bool  collapsed   = false;
    float expand      = 1.0f;
    float expand_vel  = 0.0f;

    // 记住全窗口的位置 / 尺寸，
    // 窗口松开后会弹回用户上次拖到的位置。
    ImVec2 last_full_pos  = ImVec2(60, 100);
    ImVec2 last_full_size = ImVec2(900, 620);

    // 右下角缩放把手：拖动时预览目标尺寸的圆角粗边框，
    // 不改变实际窗口；松开后窗口从当前尺寸
    // 弹性缩放到目标尺寸。
    bool   resizing               = false;
    ImVec2 resize_target_size     = ImVec2(900, 620);
    ImVec2 resize_anim_vel        = ImVec2(0, 0);
    ImVec2 resize_drag_start_mouse = ImVec2(0, 0);
    ImVec2 resize_drag_start_size  = ImVec2(900, 620);

    // 后处理辉光强度，在合成阶段生效。0 = 关闭辉光。
    float bloom_intensity = 0.75f;

    // 退出碎片动画：按下“退出”按钮后，
    // UI 碎裂成下落碎片，进程会一直运行
    // 直到动画播完（约 1.2 秒）。这些状态由 DrawUi 持有。
    bool  exit_anim_active      = false;
    bool  exit_anim_first_frame = false; // 点击帧宽限；在 DrawUi 结束时清除
    float exit_anim_start       = 0.0f;

    // 上一帧场景快照的 ImTextureID 兼容不透明句柄，
    // 由主循环通过 IRenderer::GetSceneSnapshotID() 更新，
    // 让碎裂碎片把真实 UI 作为纹理采样。
    unsigned long long scene_snapshot_id = 0;

    // 当用户在链接库弹窗打开时离开内存页，页面导航器会置位该标志；
    // 内存页消费并清除它。
    bool mem_lib_close_request = false;
};

void DrawUi(UiState* state, bool* keep_running);

// 弹窗（如链接库列表）打开时，悬浮层 Surface 会临时扩大
// （锚定在面板左上角），使弹窗可以拖出主窗口而不被裁剪。
// 实际尺寸由原生侧持有；
// 这里让 UI 请求 / 查询该状态。
void SetOverlayExpanded(bool expanded);
bool IsOverlayExpanded();

// 面板当前的屏幕位置（imgui 坐标，相对窗口原点），
// UI 用它来放置主窗口。
void GetPanelOrigin(float& x, float& y);

namespace ripple {
// 如果最后绘制的控件刚被激活，就为其记录一个 MD3 水波涟漪。
// 在需要涟漪效果的可点击控件（Selectable / Button / Combo /
// Checkbox / CollapsingHeader / ...）之后立即调用。
void TouchLastItem();
} // 命名空间 ripple

} // 命名空间 aimgui
