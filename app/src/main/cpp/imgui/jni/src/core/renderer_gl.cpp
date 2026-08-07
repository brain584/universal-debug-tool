#include "renderer.h"

#include "bloom_gl.h"

#include <EGL/egl.h>
#include <GLES3/gl3.h>
#include <cstdint>

#include "imgui.h"
#include "imgui_impl_opengl3.h"

#ifndef EGL_OPENGL_ES3_BIT
#define EGL_OPENGL_ES3_BIT 0x00000040
#endif

namespace aimgui {

namespace {

class GLRenderer final : public IRenderer {
public:
    bool Init(ANativeWindow* window, int width, int height) override {
        m_Window = window;
        m_Width = width;
        m_Height = height;

        const EGLint cfg_attribs[] = {
            EGL_BLUE_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_RED_SIZE, 8, EGL_ALPHA_SIZE, 8,
            EGL_DEPTH_SIZE, 0, EGL_STENCIL_SIZE, 0,
            EGL_RENDERABLE_TYPE, EGL_OPENGL_ES3_BIT,
            EGL_SURFACE_TYPE, EGL_WINDOW_BIT,
            EGL_NONE,
        };
        const EGLint ctx_attribs[] = { EGL_CONTEXT_CLIENT_VERSION, 3, EGL_NONE };

        m_Display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
        if (m_Display == EGL_NO_DISPLAY) return false;
        if (!eglInitialize(m_Display, nullptr, nullptr)) return false;

        EGLConfig cfg;
        EGLint n = 0;
        if (!eglChooseConfig(m_Display, cfg_attribs, &cfg, 1, &n) || n < 1) return false;

        EGLint visual = 0;
        eglGetConfigAttrib(m_Display, cfg, EGL_NATIVE_VISUAL_ID, &visual);
        ANativeWindow_setBuffersGeometry(window, 0, 0, visual);

        m_Context = eglCreateContext(m_Display, cfg, EGL_NO_CONTEXT, ctx_attribs);
        m_Surface = eglCreateWindowSurface(m_Display, cfg, window, nullptr);
        if (m_Context == EGL_NO_CONTEXT || m_Surface == EGL_NO_SURFACE) return false;
        if (!eglMakeCurrent(m_Display, m_Surface, m_Surface, m_Context)) return false;

        // Lock to vsync: the panel becomes the frame clock. eglSwapBuffers
        // blocks until the next vblank, giving a flat FPS curve at the
        // panel refresh rate with zero CPU spin.
        eglSwapInterval(m_Display, 1);

        glViewport(0, 0, width, height);
        glClearColor(0.f, 0.f, 0.f, 0.f);

        if (!ImGui_ImplOpenGL3_Init("#version 300 es")) return false;
        m_Bloom.Init(width, height); // best-effort; renderer still works if it fails
        return true;
    }

    void NewFrame() override {
        ImGui_ImplOpenGL3_NewFrame();
        ImGuiIO& io = ImGui::GetIO();
        io.DisplaySize = ImVec2((float)m_Width, (float)m_Height);
        io.DisplayFramebufferScale = ImVec2(1.0f, 1.0f);
    }

    void EndFrame() override {
        ImGui::Render();
        if (m_Bloom.Ready()) {
            m_Bloom.BeginScene();
            ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
            m_Bloom.EndSceneAndComposite();
        } else {
            glBindFramebuffer(GL_FRAMEBUFFER, 0);
            glViewport(0, 0, m_Width, m_Height);
            glClear(GL_COLOR_BUFFER_BIT);
            ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        }
        eglSwapBuffers(m_Display, m_Surface);
    }

    void Shutdown() override {
        m_Bloom.Shutdown();
        ImGui_ImplOpenGL3_Shutdown();
        if (m_Display != EGL_NO_DISPLAY) {
            eglMakeCurrent(m_Display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
            if (m_Context != EGL_NO_CONTEXT) eglDestroyContext(m_Display, m_Context);
            if (m_Surface != EGL_NO_SURFACE) eglDestroySurface(m_Display, m_Surface);
            eglTerminate(m_Display);
        }
        m_Display = EGL_NO_DISPLAY;
        m_Surface = EGL_NO_SURFACE;
        m_Context = EGL_NO_CONTEXT;
    }

    const char* Name() const override { return "OpenGL ES 3"; }

    void SetBloomIntensity(float i) override { m_Bloom.SetIntensity(i); }

    unsigned long long GetSceneSnapshotID() override {
        return (unsigned long long)(uintptr_t)m_Bloom.GetSnapshotTex();
    }

    void SetSnapshotFrozen(bool frozen) override { m_Bloom.SetSnapshotFrozen(frozen); }

private:
    ANativeWindow* m_Window = nullptr;
    EGLDisplay m_Display = EGL_NO_DISPLAY;
    EGLSurface m_Surface = EGL_NO_SURFACE;
    EGLContext m_Context = EGL_NO_CONTEXT;
    int m_Width = 0;
    int m_Height = 0;
    BloomGL m_Bloom;
};

} // namespace

std::unique_ptr<IRenderer> MakeGLRenderer() {
    return std::unique_ptr<IRenderer>(new GLRenderer());
}

} // namespace aimgui
