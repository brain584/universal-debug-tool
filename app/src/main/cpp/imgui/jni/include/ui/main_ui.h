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

// 页面切换请求（例如保存页跳转到内存页）。
// ConsumeRequestedPage() 返回待处理的请求并复位它。
void RequestPage(Page page);
int  ConsumeRequestedPage();

} // 命名空间 aimgui
