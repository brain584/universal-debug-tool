#pragma once

#include <android/native_window.h>
#include <memory>

namespace aimgui {

class IRenderer {
public:
    virtual ~IRenderer() = default;
    virtual bool Init(ANativeWindow* window, int width, int height) = 0;
    virtual void NewFrame() = 0;
    virtual void EndFrame() = 0;
    virtual void Shutdown() = 0;
    virtual const char* Name() const = 0;

    // Post-process bloom intensity (0 = off, ~1 = strong). No-op if the
    // backend's bloom isn't ready.
    virtual void SetBloomIntensity(float intensity) = 0;

    // Sampleable snapshot of the previous frame's scene image as an opaque
    // handle suitable for casting to ImTextureID (used by the exit shatter
    // animation to draw real UI chips). Returns 0 if not available.
    virtual unsigned long long GetSceneSnapshotID() = 0;

    // Freeze / unfreeze snapshot refresh. While frozen the renderer keeps
    // serving the same prev-frame scene image instead of overwriting it
    // with this frame's output — used during the exit shatter animation
    // so all chips sample the clean pre-shatter UI.
    virtual void SetSnapshotFrozen(bool frozen) = 0;
};

enum class Backend { Auto, Vulkan, OpenGL };

// Creates a renderer. With Backend::Auto it tries Vulkan first and falls back
// to OpenGL ES 3 if Vulkan is unavailable or fails to initialize.
// Returns nullptr if no backend works.
std::unique_ptr<IRenderer> MakeRenderer(ANativeWindow* window,
                                        int width, int height,
                                        Backend preferred = Backend::Auto);

// Factories for the individual backends (mostly for internal use).
std::unique_ptr<IRenderer> MakeGLRenderer();
std::unique_ptr<IRenderer> MakeVKRenderer();

} // namespace aimgui
