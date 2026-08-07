#include "bloom_gl.h"

#include <android/log.h>

#define LOG_TAG "AImGui_BloomGL"
#define LOGE(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, fmt, ##__VA_ARGS__)

namespace aimgui {

namespace {

constexpr const char* kVS = R"GLSL(#version 300 es
layout(location=0) in vec2 aPos;
out vec2 vUv;
void main() {
    vUv = aPos * 0.5 + 0.5;
    gl_Position = vec4(aPos, 0.0, 1.0);
}
)GLSL";

// Extract pixels brighter than a soft luminance threshold.
constexpr const char* kFSThreshold = R"GLSL(#version 300 es
precision mediump float;
uniform sampler2D uScene;
in vec2 vUv;
out vec4 fragColor;
void main() {
    vec3 c = texture(uScene, vUv).rgb;
    float l = dot(c, vec3(0.299, 0.587, 0.114));
    const float t = 0.30;
    float k = clamp((l - t) / max(0.01, 1.0 - t), 0.0, 1.0);
    fragColor = vec4(c * k, 1.0);
}
)GLSL";

// Separable 9-tap Gaussian (sigma ~ 2.5). uDir is one texel along the blur axis.
constexpr const char* kFSBlur = R"GLSL(#version 300 es
precision mediump float;
uniform sampler2D uImage;
uniform vec2 uDir;
in vec2 vUv;
out vec4 fragColor;
void main() {
    const float w0 = 0.2270270270;
    const float w1 = 0.1945945946;
    const float w2 = 0.1216216216;
    const float w3 = 0.0540540541;
    const float w4 = 0.0162162162;
    vec3 c  = texture(uImage, vUv).rgb * w0;
    c += texture(uImage, vUv + uDir * 1.0).rgb * w1;
    c += texture(uImage, vUv - uDir * 1.0).rgb * w1;
    c += texture(uImage, vUv + uDir * 2.0).rgb * w2;
    c += texture(uImage, vUv - uDir * 2.0).rgb * w2;
    c += texture(uImage, vUv + uDir * 3.0).rgb * w3;
    c += texture(uImage, vUv - uDir * 3.0).rgb * w3;
    c += texture(uImage, vUv + uDir * 4.0).rgb * w4;
    c += texture(uImage, vUv - uDir * 4.0).rgb * w4;
    fragColor = vec4(c, 1.0);
}
)GLSL";

// Additive composite: scene + bloom * intensity. Alpha is taken from scene
// so the overlay window stays transparent where ImGui didn't draw.
constexpr const char* kFSComposite = R"GLSL(#version 300 es
precision mediump float;
uniform sampler2D uScene;
uniform sampler2D uBloom;
uniform float uIntensity;
in vec2 vUv;
out vec4 fragColor;
void main() {
    vec4 s = texture(uScene, vUv);
    vec3 b = texture(uBloom, vUv).rgb;
    fragColor = vec4(s.rgb + b * uIntensity, s.a);
}
)GLSL";

GLuint Compile(GLenum type, const char* src) {
    GLuint s = glCreateShader(type);
    glShaderSource(s, 1, &src, nullptr);
    glCompileShader(s);
    GLint ok = 0;
    glGetShaderiv(s, GL_COMPILE_STATUS, &ok);
    if (!ok) {
        char log[1024];
        glGetShaderInfoLog(s, sizeof(log), nullptr, log);
        LOGE("shader compile failed: %s", log);
        glDeleteShader(s);
        return 0;
    }
    return s;
}

GLuint Link(GLuint vs, GLuint fs) {
    GLuint p = glCreateProgram();
    glAttachShader(p, vs);
    glAttachShader(p, fs);
    glLinkProgram(p);
    GLint ok = 0;
    glGetProgramiv(p, GL_LINK_STATUS, &ok);
    if (!ok) {
        char log[1024];
        glGetProgramInfoLog(p, sizeof(log), nullptr, log);
        LOGE("program link failed: %s", log);
        glDeleteProgram(p);
        return 0;
    }
    return p;
}

bool MakeColorAttachment(GLuint fbo, GLuint tex, int w, int h) {
    glBindTexture(GL_TEXTURE_2D, tex);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, nullptr);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glBindFramebuffer(GL_FRAMEBUFFER, fbo);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, tex, 0);
    return glCheckFramebufferStatus(GL_FRAMEBUFFER) == GL_FRAMEBUFFER_COMPLETE;
}

} // namespace

bool BloomGL::Init(int width, int height) {
    m_Width  = width;
    m_Height = height;
    m_BlurW  = width  / 2;
    m_BlurH  = height / 2;
    if (m_BlurW <= 0 || m_BlurH <= 0) return false;

    glGenFramebuffers(1, &m_SceneFBO);
    glGenTextures(1, &m_SceneTex);
    if (!MakeColorAttachment(m_SceneFBO, m_SceneTex, m_Width, m_Height)) {
        LOGE("scene FBO incomplete");
        Shutdown();
        return false;
    }

    glGenFramebuffers(2, m_BlurFBO);
    glGenTextures(2, m_BlurTex);
    for (int i = 0; i < 2; ++i) {
        if (!MakeColorAttachment(m_BlurFBO[i], m_BlurTex[i], m_BlurW, m_BlurH)) {
            LOGE("blur FBO[%d] incomplete", i);
            Shutdown();
            return false;
        }
    }

    // Snapshot texture (no FBO needed — it's only ever a copy target +
    // sample source for the shatter chips).
    glGenTextures(1, &m_PrevSceneTex);
    glBindTexture(GL_TEXTURE_2D, m_PrevSceneTex);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, m_Width, m_Height, 0, GL_RGBA, GL_UNSIGNED_BYTE, nullptr);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);

    glBindFramebuffer(GL_FRAMEBUFFER, 0);

    static const float quad[] = {
        -1.0f, -1.0f,  1.0f, -1.0f, -1.0f,  1.0f,
        -1.0f,  1.0f,  1.0f, -1.0f,  1.0f,  1.0f,
    };
    glGenVertexArrays(1, &m_QuadVAO);
    glGenBuffers(1, &m_QuadVBO);
    glBindVertexArray(m_QuadVAO);
    glBindBuffer(GL_ARRAY_BUFFER, m_QuadVBO);
    glBufferData(GL_ARRAY_BUFFER, sizeof(quad), quad, GL_STATIC_DRAW);
    glEnableVertexAttribArray(0);
    glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 0, nullptr);
    glBindVertexArray(0);

    GLuint vs  = Compile(GL_VERTEX_SHADER,   kVS);
    GLuint fsT = Compile(GL_FRAGMENT_SHADER, kFSThreshold);
    GLuint fsB = Compile(GL_FRAGMENT_SHADER, kFSBlur);
    GLuint fsC = Compile(GL_FRAGMENT_SHADER, kFSComposite);
    if (vs && fsT && fsB && fsC) {
        m_ProgThreshold = Link(vs, fsT);
        m_ProgBlur      = Link(vs, fsB);
        m_ProgComposite = Link(vs, fsC);
    }
    if (vs)  glDeleteShader(vs);
    if (fsT) glDeleteShader(fsT);
    if (fsB) glDeleteShader(fsB);
    if (fsC) glDeleteShader(fsC);
    if (!m_ProgThreshold || !m_ProgBlur || !m_ProgComposite) {
        Shutdown();
        return false;
    }

    m_LocThreshScene = glGetUniformLocation(m_ProgThreshold, "uScene");
    m_LocBlurImage   = glGetUniformLocation(m_ProgBlur,      "uImage");
    m_LocBlurDir     = glGetUniformLocation(m_ProgBlur,      "uDir");
    m_LocCompScene   = glGetUniformLocation(m_ProgComposite, "uScene");
    m_LocCompBloom   = glGetUniformLocation(m_ProgComposite, "uBloom");
    m_LocCompIntens  = glGetUniformLocation(m_ProgComposite, "uIntensity");

    m_Ready = true;
    return true;
}

void BloomGL::BeginScene() {
    if (!m_Ready) return;
    glBindFramebuffer(GL_FRAMEBUFFER, m_SceneFBO);
    glViewport(0, 0, m_Width, m_Height);
    glClearColor(0.0f, 0.0f, 0.0f, 0.0f);
    glClear(GL_COLOR_BUFFER_BIT);
}

void BloomGL::EndSceneAndComposite() {
    if (!m_Ready) return;

    // Post passes own their pipeline state.
    glDisable(GL_BLEND);
    glDisable(GL_DEPTH_TEST);
    glDisable(GL_CULL_FACE);
    glDisable(GL_SCISSOR_TEST);
    glBindVertexArray(m_QuadVAO);

    // 1) Threshold: scene (full res) -> blur[0] (half res)
    glBindFramebuffer(GL_FRAMEBUFFER, m_BlurFBO[0]);
    glViewport(0, 0, m_BlurW, m_BlurH);
    glUseProgram(m_ProgThreshold);
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, m_SceneTex);
    glUniform1i(m_LocThreshScene, 0);
    glDrawArrays(GL_TRIANGLES, 0, 6);

    // 2) Two iterations of H + V Gaussian for a wider, softer bloom.
    for (int iter = 0; iter < 2; ++iter) {
        // Horizontal: blur[0] -> blur[1]
        glBindFramebuffer(GL_FRAMEBUFFER, m_BlurFBO[1]);
        glUseProgram(m_ProgBlur);
        glActiveTexture(GL_TEXTURE0);
        glBindTexture(GL_TEXTURE_2D, m_BlurTex[0]);
        glUniform1i(m_LocBlurImage, 0);
        glUniform2f(m_LocBlurDir, 1.0f / (float)m_BlurW, 0.0f);
        glDrawArrays(GL_TRIANGLES, 0, 6);

        // Vertical: blur[1] -> blur[0]
        glBindFramebuffer(GL_FRAMEBUFFER, m_BlurFBO[0]);
        glBindTexture(GL_TEXTURE_2D, m_BlurTex[1]);
        glUniform2f(m_LocBlurDir, 0.0f, 1.0f / (float)m_BlurH);
        glDrawArrays(GL_TRIANGLES, 0, 6);
    }

    // 4) Composite scene + bloom into the default framebuffer.
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    glViewport(0, 0, m_Width, m_Height);
    glClearColor(0.0f, 0.0f, 0.0f, 0.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    glUseProgram(m_ProgComposite);
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, m_SceneTex);
    glUniform1i(m_LocCompScene, 0);
    glActiveTexture(GL_TEXTURE1);
    glBindTexture(GL_TEXTURE_2D, m_BlurTex[0]);
    glUniform1i(m_LocCompBloom, 1);
    glUniform1f(m_LocCompIntens, m_Intensity);
    glDrawArrays(GL_TRIANGLES, 0, 6);

    glBindVertexArray(0);
    glUseProgram(0);
    glActiveTexture(GL_TEXTURE0);

    // Snapshot the just-rendered scene into m_PrevSceneTex so the next
    // frame's shatter chips can sample what the UI looked like before
    // they peeled off. Skipped while frozen so chips keep sampling the
    // pre-shatter UI throughout the exit animation.
    if (!m_SnapshotFrozen) {
        glBindFramebuffer(GL_READ_FRAMEBUFFER, m_SceneFBO);
        glBindTexture(GL_TEXTURE_2D, m_PrevSceneTex);
        glCopyTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 0, 0, m_Width, m_Height);
        glBindFramebuffer(GL_READ_FRAMEBUFFER, 0);
    }
}

void BloomGL::Shutdown() {
    if (m_QuadVBO)        glDeleteBuffers(1, &m_QuadVBO);
    if (m_QuadVAO)        glDeleteVertexArrays(1, &m_QuadVAO);
    if (m_SceneFBO)       glDeleteFramebuffers(1, &m_SceneFBO);
    if (m_SceneTex)       glDeleteTextures(1, &m_SceneTex);
    if (m_PrevSceneTex)   glDeleteTextures(1, &m_PrevSceneTex);
    if (m_BlurFBO[0])     glDeleteFramebuffers(2, m_BlurFBO);
    if (m_BlurTex[0])     glDeleteTextures(2, m_BlurTex);
    if (m_ProgThreshold)  glDeleteProgram(m_ProgThreshold);
    if (m_ProgBlur)       glDeleteProgram(m_ProgBlur);
    if (m_ProgComposite)  glDeleteProgram(m_ProgComposite);

    m_QuadVBO = m_QuadVAO = 0;
    m_SceneFBO = m_SceneTex = 0;
    m_PrevSceneTex = 0;
    m_BlurFBO[0] = m_BlurFBO[1] = 0;
    m_BlurTex[0] = m_BlurTex[1] = 0;
    m_ProgThreshold = m_ProgBlur = m_ProgComposite = 0;
    m_Ready = false;
}

} // namespace aimgui
