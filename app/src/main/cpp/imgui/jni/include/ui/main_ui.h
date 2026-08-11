#pragma once
#include <cstdint>

namespace aimgui {

struct UiState;  // 前向声明，必须在 enum class Page 之前

enum class Page : uint8_t {
    SelectProcess,
    Search,
    Memory,
    Breakpoint,
    Save,
    Script,
    Settings
};

struct PageItem {
    Page        id;
    const char* label;
};

extern const PageItem kPages[];
extern const int      kPagesCount;

void DrawPage(UiState* state, Page page);

// 目标进程存活检查（进程销毁后自动重置状态），每帧调用，
// 内部限频。定义于 main_ui.cpp。
void CheckTargetAlive();

// 启动时读取一次内存类型配置（App 私有 files 目录）。
void LoadMemTypeConfigOnce();

// 页面切换请求（例如保存页跳转到内存页）。
// ConsumeRequestedPage() 返回待处理的请求并复位它。
void RequestPage(Page page);
int  ConsumeRequestedPage();

} // 命名空间 aimgui
