#pragma once

#include <GLES3/gl3.h>

namespace aimgui {

// Tiny post-process bloom for the OpenGL ES 3 backend.
//
// Usage in IRenderer::EndFrame:
//
//   if (bloom.Ready()) {
//       bloom.BeginScene();                                // bind scene FBO
//       ImGui_ImplOpenGL3_RenderDrawData(...);
//       bloom.EndSceneAndComposite();                      // threshold + blur + composite to default FB
//   } else {
//       glClear(GL_COLOR_BUFFER_BIT);
//       ImGui_ImplOpenGL3_RenderDrawData(...);
//   }
//
// The composite preserves the scene's alpha channel so the SurfaceFlinger
// overlay still shows through where ImGui didn't draw.
class BloomGL {
public:
    bool Init(int width, int height);
    void Shutdown();
    bool Ready() const { return m_Ready; }

    void SetIntensity(float i) { m_Intensity = i; }
    void SetSnapshotFrozen(bool frozen) { m_SnapshotFrozen = frozen; }

    // GL texture handle of last frame's scene image. Sampleable as a
    // regular texture (ImTextureID = (intptr_t)tex). Returns 0 if bloom
    // isn't initialised.
    unsigned int GetSnapshotTex() const { return m_PrevSceneTex; }

    void BeginScene();
    void EndSceneAndComposite();

private:
    bool m_Ready  = false;
    int  m_Width  = 0;
    int  m_Height = 0;
    int  m_BlurW  = 0;
    int  m_BlurH  = 0;
    float m_Intensity     = 0.75f;
    bool  m_SnapshotFrozen = false;

    GLuint m_SceneFBO     = 0;
    GLuint m_SceneTex     = 0;
    GLuint m_PrevSceneTex = 0; // snapshot of previous frame's scene image
    GLuint m_BlurFBO[2]   = { 0, 0 };
    GLuint m_BlurTex[2]   = { 0, 0 };

    GLuint m_QuadVAO = 0;
    GLuint m_QuadVBO = 0;

    GLuint m_ProgThreshold = 0;
    GLuint m_ProgBlur      = 0;
    GLuint m_ProgComposite = 0;

    GLint  m_LocThreshScene = -1;
    GLint  m_LocBlurImage   = -1;
    GLint  m_LocBlurDir     = -1;
    GLint  m_LocCompScene   = -1;
    GLint  m_LocCompBloom   = -1;
    GLint  m_LocCompIntens  = -1;
};

} // namespace aimgui
