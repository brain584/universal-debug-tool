#include "ui/ui.h"
#include "ui/main_ui.h"

#include "imgui.h"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "socket/socket.h"

namespace aimgui {

// ── MD3 水波涟漪管理器 ──
// 当最后一个绘制的 ImGui 控件被激活时，
// 记录其点击位置与矩形，然后在前景绘制列表上
// 绘制一个向外扩散的白色裁剪高亮。
namespace ripple {

namespace {
struct Entry {
    ImGuiID id;
    ImVec2  origin;
    ImVec2  rect_min;
    ImVec2  rect_max;
    float   start;
};
std::vector<Entry> g_ripples;
} // 匿名命名空间

void TouchLastItem() {
    if (!ImGui::IsItemActivated()) return;
    Entry e;
    e.id       = ImGui::GetItemID();
    e.origin   = ImGui::GetIO().MousePos;
    e.rect_min = ImGui::GetItemRectMin();
    e.rect_max = ImGui::GetItemRectMax();
    e.start    = (float)ImGui::GetTime();
    g_ripples.push_back(e);
}

void DrawAll() {
    const float now      = (float)ImGui::GetTime();
    const float duration = 0.55f;

    auto& v = g_ripples;
    for (auto it = v.begin(); it != v.end(); ) {
        const float t = (now - it->start) / duration;
        if (t >= 1.0f) { it = v.erase(it); continue; }

        const float ease   = 1.0f - (1.0f - t) * (1.0f - t); // 二次缓出
        const float dx     = it->rect_max.x - it->rect_min.x;
        const float dy     = it->rect_max.y - it->rect_min.y;
        const float max_r  = std::sqrt(dx * dx + dy * dy);
        const float radius = ease * max_r;
        const float alpha  = (1.0f - t) * 0.22f;

        ImDrawList* dl = ImGui::GetForegroundDrawList();
        dl->PushClipRect(it->rect_min, it->rect_max, true);
        dl->AddCircleFilled(it->origin, radius,
                            ImGui::GetColorU32(ImVec4(1.0f, 1.0f, 1.0f, alpha)),
                            48);
        dl->PopClipRect();
        ++it;
    }
}

} // 命名空间 ripple

namespace {

// ── 退出碎片动画 ──
// 点击退出时生成约 90 个旋转、受重力影响的小碎片，
// 覆盖当前 Surface 区域，其余 UI 渐隐为 0，
// 动画播完后通知主循环退出。
namespace shatter {

struct Chip {
    ImVec2 pos;       // 当前 Surface 坐标中心
    ImVec2 vel;
    float  rot;
    float  rot_vel;
    ImVec2 size;
    ImU32  color;     // 无快照纹理时的备用纯色
    ImVec2 uv0;       // 场景快照上的左上 UV（生成时设置）
    ImVec2 uv1;       // 场景快照上的右下 UV（生成时设置）
};

std::vector<Chip> g_chips;

uint32_t g_seed = 0x9e3779b9;
uint32_t Rand() {
    g_seed ^= g_seed << 13;
    g_seed ^= g_seed >> 17;
    g_seed ^= g_seed << 5;
    return g_seed;
}
float Frand(float lo, float hi) {
    return lo + ((Rand() & 0xFFFF) / 65535.0f) * (hi - lo);
}

void SubdivideChip(const ImVec2& mn, const ImVec2& mx, int depth,
                   float dw, float dh, const ImU32* palette) {
    const float w = mx.x - mn.x;
    const float h = mx.y - mn.y;
    constexpr float kMinSize  = 18.0f;
    constexpr int   kMaxDepth = 7;

    const bool stop = depth >= kMaxDepth
                   || w < kMinSize * 2.0f
                   || h < kMinSize * 2.0f
                   || (depth > 2 && Frand(0.0f, 1.0f) < 0.30f);

    if (stop) {
        Chip c;
        c.pos     = ImVec2((mn.x + mx.x) * 0.5f, (mn.y + mx.y) * 0.5f);
        c.size    = ImVec2(w, h);
        c.uv0     = ImVec2(mn.x / dw, mn.y / dh);
        c.uv1     = ImVec2(mx.x / dw, mx.y / dh);

        const float area  = w * h;
        const float kRef  = 60.0f * 60.0f;
        float mass        = std::sqrt(area / kRef);
        if (mass < 0.5f) mass = 0.5f;
        if (mass > 1.8f) mass = 1.8f;
        const float inv   = 1.0f / mass;

        c.vel     = ImVec2(Frand(-280.0f, 280.0f) * inv,
                           Frand(-540.0f, -90.0f) * inv);
        c.rot     = 0.0f;
        c.rot_vel = Frand(-5.5f, 5.5f) * inv;
        c.color   = palette[(uint32_t)(c.pos.x + c.pos.y) & 3u];
        g_chips.push_back(c);
        return;
    }

    if (w > h) {
        const float t  = 0.5f + Frand(-0.18f, 0.18f);
        const float sx = mn.x + w * t;
        SubdivideChip(mn, ImVec2(sx, mx.y), depth + 1, dw, dh, palette);
        SubdivideChip(ImVec2(sx, mn.y), mx, depth + 1, dw, dh, palette);
    } else {
        const float t  = 0.5f + Frand(-0.18f, 0.18f);
        const float sy = mn.y + h * t;
        SubdivideChip(mn, ImVec2(mx.x, sy), depth + 1, dw, dh, palette);
        SubdivideChip(ImVec2(mx.x, sy), mx, depth + 1, dw, dh, palette);
    }
}

void Begin(const ImVec2& origin, const ImVec2& size,
           float display_w, float display_h) {
    g_chips.clear();
    g_chips.reserve(200);

    const ImU32 palette[4] = {
        ImGui::GetColorU32(ImGuiCol_TitleBgActive),
        ImGui::GetColorU32(ImVec4(0.22f, 0.40f, 0.78f, 1.0f)),
        ImGui::GetColorU32(ImGuiCol_FrameBg),
        ImGui::GetColorU32(ImVec4(0.30f, 0.62f, 1.0f, 1.0f)),
    };

    SubdivideChip(origin,
                  ImVec2(origin.x + size.x, origin.y + size.y),
                  0, display_w, display_h, palette);
}

void Step(float dt, float t01, ImTextureID snapshot_tex) {
    constexpr float kGravity = 1800.0f; // 像素 / 秒^2

    ImDrawList* dl = ImGui::GetForegroundDrawList();
    for (auto& c : g_chips) {
        const float area = c.size.x * c.size.y;
        float mass = std::sqrt(area / (60.0f * 60.0f));
        if (mass < 0.5f) mass = 0.5f;
        if (mass > 1.8f) mass = 1.8f;

        c.vel.y += kGravity * mass * dt;
        c.pos.x += c.vel.x * dt;
        c.pos.y += c.vel.y * dt;
        c.rot   += c.rot_vel * dt;

        const float cs = std::cos(c.rot);
        const float sn = std::sin(c.rot);
        const float hx = c.size.x * 0.5f;
        const float hy = c.size.y * 0.5f;
        const ImVec2 corners[4] = {
            ImVec2(c.pos.x + (-hx * cs - -hy * sn), c.pos.y + (-hx * sn + -hy * cs)),
            ImVec2(c.pos.x + ( hx * cs - -hy * sn), c.pos.y + ( hx * sn + -hy * cs)),
            ImVec2(c.pos.x + ( hx * cs -  hy * sn), c.pos.y + ( hx * sn +  hy * cs)),
            ImVec2(c.pos.x + (-hx * cs -  hy * sn), c.pos.y + (-hx * sn +  hy * cs)),
        };

        const float fade = 1.0f - t01;
        const uint32_t a = (uint32_t)(255.0f * fade);

        if (snapshot_tex) {
            const ImU32 tint = 0x00FFFFFFu | (a << 24);
            dl->AddImageQuad(snapshot_tex,
                             corners[0], corners[1], corners[2], corners[3],
                             ImVec2(c.uv0.x, c.uv0.y),
                             ImVec2(c.uv1.x, c.uv0.y),
                             ImVec2(c.uv1.x, c.uv1.y),
                             ImVec2(c.uv0.x, c.uv1.y),
                             tint);
        } else {
            const ImU32 col = (c.color & 0x00FFFFFFu) | (a << 24);
            dl->AddQuadFilled(corners[0], corners[1], corners[2], corners[3], col);
        }
    }
}

} // 命名空间 shatter


void ApplyStyleOnce() {
    // 渲染器在关闭、收起和缩放时会销毁 / 重建 ImGui 上下文；
    // 因此每帧无条件应用样式，
    // 确保任何上下文（包括复用指针）都呈现预期外观。
    auto& s = ImGui::GetStyle();
    s.WindowRounding          = 12.0f;
    s.ChildRounding           = 10.0f;
    s.FrameRounding           = 6.0f;
    s.GrabRounding            = 6.0f;
    s.PopupRounding           = 6.0f;
    s.ScrollbarRounding       = 10.0f;
    s.WindowBorderSize        = 1.0f;
    s.FrameBorderSize         = 0.0f;
    s.WindowPadding           = ImVec2(0, 0);
    s.ItemSpacing             = ImVec2(14, 10);
    s.ItemInnerSpacing        = ImVec2(8, 6);
    s.FramePadding            = ImVec2(14, 10);
    s.ScrollbarSize           = 26.0f;
    s.GrabMinSize             = 16.0f;
    s.SeparatorTextBorderSize = 3.0f;
    s.SeparatorTextPadding    = ImVec2(28, 8);

    s.Colors[ImGuiCol_TitleBg]          = s.Colors[ImGuiCol_TitleBgActive];
    s.Colors[ImGuiCol_TitleBgCollapsed] = s.Colors[ImGuiCol_TitleBgActive];
}

// ── 侧边栏 ──
void DrawSidebar(Page& current, bool* keep_running, UiState* state) {
    constexpr float kInnerPadX     = 18.0f;
    constexpr float kInnerPadY     = 14.0f;
    constexpr float kSelectableH   = 44.0f;
    constexpr float kAccentInset   = 10.0f;
    constexpr float kAccentW       = 4.0f;
    constexpr float kFooterH       = 110.0f;
    constexpr float kBottomMargin  = 16.0f;

    const ImVec4 sel_bg(0.22f, 0.40f, 0.78f, 0.55f);
    ImGui::PushStyleColor(ImGuiCol_ChildBg,       ImVec4(0.07f, 0.08f, 0.10f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Header,        sel_bg);
    ImGui::PushStyleColor(ImGuiCol_HeaderHovered, sel_bg);
    ImGui::PushStyleColor(ImGuiCol_HeaderActive,  sel_bg);

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,       ImVec2(kInnerPadX, kInnerPadY));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,         ImVec2(0, 4));
    ImGui::PushStyleVar(ImGuiStyleVar_SelectableTextAlign, ImVec2(0.08f, 0.5f));
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,        ImVec2(0, 6));

    ImGui::BeginChild("##sidebar", ImVec2(230, 0),
                      ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding,
                      ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::PushTextWrapPos(0.0f);

    const ImU32 accent = ImGui::GetColorU32(ImVec4(0.30f, 0.62f, 1.0f, 1.0f));
    for (int i = 0; i < kPagesCount; ++i) {
        const PageItem& p = kPages[i];
        bool selected = (current == p.id);
        if (ImGui::Selectable(p.label, selected, 0, ImVec2(0, kSelectableH))) {
            current = p.id;
        }
        ripple::TouchLastItem();
        if (selected) {
            ImVec2 a = ImGui::GetItemRectMin();
            ImVec2 b = ImGui::GetItemRectMax();
            ImGui::GetWindowDrawList()->AddRectFilled(
                ImVec2(a.x - kAccentInset,            a.y + 8),
                ImVec2(a.x - kAccentInset + kAccentW, b.y - 8),
                accent, kAccentW * 0.5f);
        }
    }

    float remaining = ImGui::GetWindowHeight() - ImGui::GetCursorPosY() - kFooterH - kBottomMargin;
    if (remaining > 0) ImGui::Dummy(ImVec2(0, remaining));

    ImGui::Separator();
    ImGui::Spacing();
    ImGui::TextDisabled("%s", state->renderer_name ? state->renderer_name : "?");
    ImGui::Spacing();

    // SO 加密通道状态（悬浮层打开时始终可见）
    {
        std::string conn = g_socket.StatusText();
        const ImVec4 col = g_socket.IsConnected()
                               ? ImVec4(0.32f, 0.90f, 0.45f, 1.0f)
                               : (g_socket.IsConnecting()
                                      ? ImVec4(0.95f, 0.72f, 0.20f, 1.0f)
                                      : ImVec4(0.85f, 0.35f, 0.35f, 1.0f));
        ImGui::TextColored(col, "%s", conn.c_str());
    }
    ImGui::Spacing();

    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 12));
    if (ImGui::Button(u8"退出", ImVec2(-1, 0))) {
        if (!state->exit_anim_active) {
            // UV 归一化使用“快照纹理”的尺寸，
            // 即 io.DisplaySize。Surface 就是 imgui 面板窗口，
            // 因此碎片从 Surface 原点飞出。
            const ImGuiIO& io2 = ImGui::GetIO();
            shatter::Begin(ImVec2(0, 0), io2.DisplaySize,
                           io2.DisplaySize.x, io2.DisplaySize.y);
            state->exit_anim_active      = true;
            state->exit_anim_first_frame = true;
            state->exit_anim_start       = (float)ImGui::GetTime();
        }
    }
    ripple::TouchLastItem();
    ImGui::PopStyleVar();

    ImGui::Dummy(ImVec2(0, kBottomMargin));

    ImGui::PopTextWrapPos();
    ImGui::EndChild();

    ImGui::PopStyleVar(4);
    ImGui::PopStyleColor(4);
}

// 前向声明——函数体在下方，但 DrawContent 需要先调用它。
void DrawResizeGrip(const UiState* state);

void DrawContent(UiState* state, Page page) {
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(22, 18));

    // HorizontalScrollbar：当页面内容
    // （堆栈链条、长行等）超出面板宽度时自动显示横向滚动条，
    // 避免内容被裁剪 / 无法触达。页面级不自动换行（-1.0f），
    // 让长行真正撑宽内容并触发滚动条；
    // 显式 TextWrapped() 调用仍会换行。
    ImGui::BeginChild("##content", ImVec2(0, 0),
                      ImGuiChildFlags_AlwaysUseWindowPadding,
                      ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::PushTextWrapPos(-1.0f);
    DrawPage(state, page);
    DrawResizeGrip(state);
    ImGui::PopTextWrapPos();
    ImGui::EndChild();

    ImGui::PopStyleVar();
}

void DrawIslandContent() {
    ImGuiIO& io = ImGui::GetIO();
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.0f FPS", io.Framerate);

    ImVec2 ts = ImGui::CalcTextSize(buf);
    ImVec2 ws = ImGui::GetWindowSize();
    ImGui::SetCursorPos(ImVec2((ws.x - ts.x) * 0.5f,
                               (ws.y - ts.y) * 0.5f));
    ImGui::TextUnformatted(buf);
}

// 右下角把手矩形（Surface / 屏幕坐标；窗口锚定在
// Surface 原点 (0,0)）。
ImVec2 GripMin(const UiState* state) {
    constexpr float kGrip = 40.0f;
    return ImVec2(state->last_full_size.x - kGrip,
                  state->last_full_size.y - kGrip);
}
ImVec2 GripMax(const UiState* state) {
    return ImVec2(state->last_full_size.x, state->last_full_size.y);
}

// 缩放在 Begin 之前检测，使 NoMove 能在当前帧生效。
// 命中测试用裸数学计算，因为 ImGui::IsMouseHoveringRect 默认
// 会按当前窗口 ClipRect 裁剪。
void HandleResizeInput(UiState* state, const ImGuiIO& io) {
    const ImVec2 grip_min = GripMin(state);
    const ImVec2 grip_max = GripMax(state);

    const bool inside = io.MousePos.x >= grip_min.x && io.MousePos.x < grip_max.x &&
                        io.MousePos.y >= grip_min.y && io.MousePos.y < grip_max.y;

    if (io.MouseClicked[0] && !state->resizing && inside) {
        state->resizing                = true;
        state->resize_drag_start_mouse = io.MousePos;
        state->resize_drag_start_size  = state->last_full_size;
        state->resize_target_size      = state->last_full_size;
    }
    if (state->resizing && io.MouseDown[0]) {
        const ImVec2 d(io.MousePos.x - state->resize_drag_start_mouse.x,
                       io.MousePos.y - state->resize_drag_start_mouse.y);
        state->resize_target_size = ImVec2(
            std::max(700.0f, state->resize_drag_start_size.x + d.x),
            std::max(560.0f, state->resize_drag_start_size.y + d.y));
    }
    if (state->resizing && !io.MouseDown[0]) {
        state->resizing        = false;
        state->resize_anim_vel = ImVec2(0, 0);
    }
}

// 仅视觉效果：缩放时显示角点圆点 + 预览框。
void DrawResizeGrip(const UiState* state) {
    const ImVec2 grip_min = GripMin(state);
    const ImVec2 grip_max = GripMax(state);

    const bool inside = ImGui::IsMouseHoveringRect(grip_min, grip_max);
    ImDrawList* fg = ImGui::GetForegroundDrawList();
    const ImU32 col = ImGui::GetColorU32(
        state->resizing ? ImGuiCol_ResizeGripActive
                        : (inside ? ImGuiCol_ResizeGripHovered : ImGuiCol_ResizeGrip));

    for (int i = 0; i < 3; ++i) {
        const float o = 8.0f + i * 7.0f;
        fg->AddLine(ImVec2(grip_max.x - o, grip_max.y - 5),
                    ImVec2(grip_max.x - 5, grip_max.y - o),
                    col, 3.0f);
    }

    if (state->resizing) {
        const ImVec2 a(0, 0);
        const ImVec2 b(a.x + state->resize_target_size.x,
                       a.y + state->resize_target_size.y);
        fg->AddRect(a, b,
                    ImGui::GetColorU32(ImVec4(0.30f, 0.62f, 1.0f, 0.95f)),
                    12.0f, 5.0f, 0);
    }
}

} // 匿名命名空间

void DrawUi(UiState* state, bool* keep_running) {
    ApplyStyleOnce();

    ImGuiIO& io = ImGui::GetIO();
    const float dt = io.DeltaTime > 0.0f ? io.DeltaTime : 1.0f / 60.0f;

    // 点击帧之后主窗口停止渲染；
    // 碎片采样点击前冻结的场景快照，
    // 在视觉上替代 UI。
    if (state->exit_anim_active && !state->exit_anim_first_frame) {
        const float now     = (float)ImGui::GetTime();
        const float t01     = (now - state->exit_anim_start) / 1.2f;
        const float clamped = t01 < 0.0f ? 0.0f : (t01 > 1.0f ? 1.0f : t01);

        ripple::DrawAll();
        shatter::Step(dt, clamped,
                      (ImTextureID)(uintptr_t)state->scene_snapshot_id);

        if (t01 >= 1.0f) {
            state->exit_anim_active = false;
            *keep_running = false;
        }
        return;
    }

    // 先处理把手的按下 / 拖动 / 松开，让 NoMove 在当前帧生效。
    HandleResizeInput(state, io);

    // 即时缩放：直接应用拖动目标尺寸（无弹簧动画）。
    if (!state->resizing) {
        state->last_full_size = state->resize_target_size;
    } else {
        // 让实际窗口保持拖动开始时的尺寸；
        // 预览框从 resize_target_size 读取目标尺寸。
        state->last_full_size = state->resize_drag_start_size;
    }

    const bool collapsed = state->collapsed;
    const bool show_chrome = !collapsed;

    constexpr float kIslandH = 56.0f;

    // 单窗口悬浮层：SurfaceView 的 Surface 就是 imgui 面板
    // 窗口，因此 ImGui 窗口锚定在 Surface 原点 (0,0)
    // 并铺满整个屏幕。面板在屏幕上的移动 / 缩放
    // 由应用移动 / 缩放悬浮窗口完成。
    // 弹窗打开时窗口可能临时全屏；
    // 按跟踪的屏幕位置 / 尺寸绘制面板（主窗口），
    // 使其保持原位且仍可拖动。
    float ppx = 0.0f, ppy = 0.0f;
    GetPanelOrigin(ppx, ppy);
    ImGui::SetNextWindowPos(ImVec2(ppx, ppy));
    ImGui::SetNextWindowSize(collapsed ? ImVec2(280.0f, 56.0f)
                                       : state->last_full_size,
                             ImGuiCond_Always);

    const float rounding = collapsed ? (kIslandH * 0.5f) : 12.0f;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, rounding);

    // NoMove：窗口位置由应用持有（拖动时应用移动 Surface 窗口）；
    // NoResize：自定义把手负责缩放。
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoMove |
                             ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoCollapse |
                             ImGuiWindowFlags_NoSavedSettings;
    if (!show_chrome) {
        flags |= ImGuiWindowFlags_NoTitleBar;
    }

    char title[64];
    std::snprintf(title, sizeof(title), "Alive  v%s###aimgui_main", ImGui::GetVersion());

    // 标题栏 X 收起面板而不是关闭应用：传入
    // 一次性标志让 ImGui 绘制关闭按钮，
    // 然后在 End() 之后把点击转为收起。
    bool close_requested = true;
    bool* p_open = show_chrome ? &close_requested : nullptr;

    if (ImGui::Begin(title, p_open, flags)) {
        if (collapsed) {
            // 收起状态：应用把悬浮窗口缩小为 280x56
            // 的胶囊，整个显示区域就是胶囊。
            DrawIslandContent();
            if (ImGui::IsWindowHovered() && ImGui::IsMouseClicked(0)) {
                state->collapsed = false;
            }
        } else {
            static Page page = Page::SelectProcess;
            const Page prev_page = page;
            DrawSidebar(page, keep_running, state);
            // 链接库弹窗打开时离开内存页：释放
            // Surface 扩展并请求关闭弹窗。
            if (page != prev_page) {
                SetOverlayExpanded(false);
                state->mem_lib_close_request = true;
            }
            // 处理页面发起的切换请求（例如保存页的
            // “跳转到内存页”）。在离开检查之后应用，
            // 这样程序化切换不会触发关闭请求。
            const int page_req = ConsumeRequestedPage();
            if (page_req >= 0)
                page = (Page)page_req;
            ImGui::SameLine(0, 0);
            DrawContent(state, page);
        }
    }
    ImGui::End();

    if (collapsed) {
        // 胶囊没有子窗口；释放任何弹窗扩展
        //（收起时不会调用 DrawPage）。
        SetOverlayExpanded(false);
    }

    if (!close_requested) {
        close_requested = true;
        state->collapsed = true;   // X = 收起
    }

    ImGui::PopStyleVar();   // 还原 WindowRounding

    // 前景覆盖层：在每个可点击控件上绘制水波涟漪。
    ripple::DrawAll();

    // 点击帧仍需推进 / 绘制碎片，
    // 使画面与下一帧保持连续。
    if (state->exit_anim_active && state->exit_anim_first_frame) {
        const float now     = (float)ImGui::GetTime();
        const float t01     = (now - state->exit_anim_start) / 1.2f;
        const float clamped = t01 < 0.0f ? 0.0f : (t01 > 1.0f ? 1.0f : t01);
        shatter::Step(dt, clamped,
                      (ImTextureID)(uintptr_t)state->scene_snapshot_id);
        state->exit_anim_first_frame = false;
    }
}

} // 命名空间 aimgui
