#pragma once

#include "renderer.h"

struct ANativeWindow;

namespace aimgui {

// Owns the (ANativeWindow, IRenderer) pair. Rebuild() tears down and
// recreates both — used when toggling permeate_record (which needs a fresh
// SurfaceFlinger layer) so the main loop doesn't have to know the order.
class WindowSession {
public:
    ~WindowSession() { Destroy(); }
    bool Build(int side, bool permeate_record);
    void Destroy();
    IRenderer* renderer() const { return m_Renderer.get(); }
private:
    ANativeWindow*             m_Window = nullptr;
    std::unique_ptr<IRenderer> m_Renderer;
};

} // namespace aimgui
