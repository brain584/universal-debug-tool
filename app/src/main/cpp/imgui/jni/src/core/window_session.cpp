#include "window_session.h"

#include "platform/ANativeWindowCreator.h"

namespace aimgui {

bool WindowSession::Build(int side, bool permeate_record) {
    m_Window = android::ANativeWindowCreator::Create("AImGui", side, side,
                                                     permeate_record);
    if (!m_Window) return false;
    m_Renderer = MakeRenderer(m_Window, side, side, Backend::Auto);
    if (!m_Renderer) {
        android::ANativeWindowCreator::Destroy(m_Window);
        m_Window = nullptr;
        return false;
    }
    return true;
}

void WindowSession::Destroy() {
    if (m_Renderer) { m_Renderer->Shutdown(); m_Renderer.reset(); }
    if (m_Window)   { android::ANativeWindowCreator::Destroy(m_Window); m_Window = nullptr; }
}

} // namespace aimgui
