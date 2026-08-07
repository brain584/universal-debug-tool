#include "renderer.h"

#include "bloom_vk.h"
#include "vulkan_wrapper.h"
#include <vulkan/vulkan_android.h>

#include "imgui.h"
#include "imgui_impl_vulkan.h"

#include <android/log.h>
#include <android/native_window.h>
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <unistd.h>
#include <vector>

#define LOG_TAG "AImGui_VK"
#define LOGE(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, fmt, ##__VA_ARGS__)

namespace aimgui {

namespace {

static void check_vk(VkResult err) {
    if (err != VK_SUCCESS) {
        LOGE("VkResult = %d", err);
    }
}

class VKRenderer final : public IRenderer {
public:
    bool Init(ANativeWindow* window, int width, int height) override {
        m_Window = window;
        m_Width  = width;
        m_Height = height;

        if (InitVulkan() != 1) {
            LOGE("Vulkan loader unavailable: %s", dlerror());
            return false;
        }

        void* libvulkan = dlopen("libvulkan.so", RTLD_NOW);
        ImGui_ImplVulkan_LoadFunctions(0,
            [](const char* name, void* user) -> PFN_vkVoidFunction {
                return reinterpret_cast<PFN_vkVoidFunction>(dlsym(user, name));
            }, libvulkan);

        if (!CreateInstance()) return false;
        if (!SelectPhysicalDevice()) return false;
        if (!CreateLogicalDevice()) return false;
        if (!CreateDescriptorPool()) return false;
        if (!CreateSurfaceAndSwapchain()) return false;

        // Try to set up the bloom pipeline. If it fails for any reason the
        // renderer falls back to direct-to-swapchain ImGui rendering.
        if (m_Bloom.Init(m_Device, m_PhysicalDevice, m_DescPool,
                         m_WD->SurfaceFormat.format, m_Width, m_Height)) {
            if (!m_Bloom.BindToSwapchainRenderPass(m_WD->RenderPass)) {
                m_Bloom.Shutdown();
            }
        }

        SetupImGuiBackend();

        // Now that ImGui's Vulkan impl has its descriptor pool wired up,
        // hand it the prev-scene image so shatter chips can sample real UI.
        if (m_Bloom.Ready()) m_Bloom.RegisterImGuiSnapshot();

        return true;
    }

    void NewFrame() override {
        if (m_SwapChainRebuild) RebuildSwapchain();
        ImGui_ImplVulkan_NewFrame();

        ImGuiIO& io = ImGui::GetIO();
        io.DisplaySize = ImVec2((float)m_Width, (float)m_Height);
        io.DisplayFramebufferScale = ImVec2(1.0f, 1.0f);
    }

    void EndFrame() override {
        ImGui::Render();
        ImDrawData* draw = ImGui::GetDrawData();
        if (!draw || draw->DisplaySize.x <= 0 || draw->DisplaySize.y <= 0) return;
        Submit(draw);
    }

    void Shutdown() override {
        if (m_Device == VK_NULL_HANDLE) return;
        vkDeviceWaitIdle(m_Device);
        m_Bloom.Shutdown();
        ImGui_ImplVulkan_Shutdown();
        if (m_WD) {
            ImGui_ImplVulkanH_DestroyWindow(m_Instance, m_Device, m_WD, nullptr);
            delete m_WD;
            m_WD = nullptr;
        }
        if (m_DescPool != VK_NULL_HANDLE) vkDestroyDescriptorPool(m_Device, m_DescPool, nullptr);
        vkDestroyDevice(m_Device, nullptr);
        vkDestroyInstance(m_Instance, nullptr);
        m_Device = VK_NULL_HANDLE;
        m_Instance = VK_NULL_HANDLE;
    }

    const char* Name() const override { return "Vulkan"; }

    void SetBloomIntensity(float i) override { m_Bloom.SetIntensity(i); }

    unsigned long long GetSceneSnapshotID() override {
        return (unsigned long long)(uintptr_t)m_Bloom.GetSnapshotDescriptorSet();
    }

    void SetSnapshotFrozen(bool frozen) override { m_Bloom.SetSnapshotFrozen(frozen); }

private:
    bool CreateInstance() {
        const char* exts[] = { "VK_KHR_surface", "VK_KHR_android_surface" };
        VkApplicationInfo ai{};
        ai.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
        ai.pApplicationName = "AImGui";
        ai.apiVersion = VK_MAKE_VERSION(1, 1, 0);

        VkInstanceCreateInfo ci{};
        ci.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
        ci.pApplicationInfo = &ai;
        ci.enabledExtensionCount = 2;
        ci.ppEnabledExtensionNames = exts;
        return vkCreateInstance(&ci, nullptr, &m_Instance) == VK_SUCCESS;
    }

    bool SelectPhysicalDevice() {
        uint32_t n = 0;
        vkEnumeratePhysicalDevices(m_Instance, &n, nullptr);
        if (n == 0) return false;
        std::vector<VkPhysicalDevice> gpus(n);
        vkEnumeratePhysicalDevices(m_Instance, &n, gpus.data());
        for (auto g : gpus) {
            VkPhysicalDeviceProperties p;
            vkGetPhysicalDeviceProperties(g, &p);
            if (p.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU) {
                m_PhysicalDevice = g;
                return true;
            }
        }
        m_PhysicalDevice = gpus[0];
        return true;
    }

    bool CreateLogicalDevice() {
        uint32_t n = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(m_PhysicalDevice, &n, nullptr);
        std::vector<VkQueueFamilyProperties> qs(n);
        vkGetPhysicalDeviceQueueFamilyProperties(m_PhysicalDevice, &n, qs.data());
        for (uint32_t i = 0; i < n; ++i) {
            if (qs[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) { m_QueueFamily = i; break; }
        }
        if (m_QueueFamily == UINT32_MAX) return false;

        const char* dext[] = { "VK_KHR_swapchain" };
        const float priority = 1.0f;
        VkDeviceQueueCreateInfo qci{};
        qci.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
        qci.queueFamilyIndex = m_QueueFamily;
        qci.queueCount = 1;
        qci.pQueuePriorities = &priority;

        VkDeviceCreateInfo dci{};
        dci.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
        dci.queueCreateInfoCount = 1;
        dci.pQueueCreateInfos = &qci;
        dci.enabledExtensionCount = 1;
        dci.ppEnabledExtensionNames = dext;
        if (vkCreateDevice(m_PhysicalDevice, &dci, nullptr, &m_Device) != VK_SUCCESS) return false;
        vkGetDeviceQueue(m_Device, m_QueueFamily, 0, &m_Queue);
        return true;
    }

    bool CreateDescriptorPool() {
        VkDescriptorPoolSize sizes[] = {
            { VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER, 64 },
        };
        VkDescriptorPoolCreateInfo ci{};
        ci.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
        ci.flags = VK_DESCRIPTOR_POOL_CREATE_FREE_DESCRIPTOR_SET_BIT;
        ci.maxSets = 64;
        ci.poolSizeCount = 1;
        ci.pPoolSizes = sizes;
        return vkCreateDescriptorPool(m_Device, &ci, nullptr, &m_DescPool) == VK_SUCCESS;
    }

    bool CreateSurfaceAndSwapchain() {
        m_WD = new ImGui_ImplVulkanH_Window();

        VkAndroidSurfaceCreateInfoKHR sci{};
        sci.sType = VK_STRUCTURE_TYPE_ANDROID_SURFACE_CREATE_INFO_KHR;
        sci.window = m_Window;
        VkSurfaceKHR surface;
        if (vkCreateAndroidSurfaceKHR(m_Instance, &sci, nullptr, &surface) != VK_SUCCESS) return false;
        m_WD->Surface = surface;

        VkBool32 supported = VK_FALSE;
        vkGetPhysicalDeviceSurfaceSupportKHR(m_PhysicalDevice, m_QueueFamily, surface, &supported);
        if (!supported) return false;

        const VkFormat fmts[] = {
            VK_FORMAT_B8G8R8A8_UNORM, VK_FORMAT_R8G8B8A8_UNORM,
            VK_FORMAT_B8G8R8_UNORM,   VK_FORMAT_R8G8B8_UNORM,
        };
        m_WD->SurfaceFormat = ImGui_ImplVulkanH_SelectSurfaceFormat(
            m_PhysicalDevice, surface, fmts, IM_ARRAYSIZE(fmts), VK_COLORSPACE_SRGB_NONLINEAR_KHR);

        // FIFO is hard vsync — the panel's vblank becomes our frame clock,
        // giving a flat refresh-rate-bound FPS without any CPU spin (the
        // wait happens inside vkAcquireNextImageKHR as the OS schedules us
        // off the CPU between frames). For target rates below the panel
        // refresh, main.cpp's drift-corrected sleep_until adds the gap.
        VkPresentModeKHR modes[] = { VK_PRESENT_MODE_FIFO_KHR };
        m_WD->PresentMode = ImGui_ImplVulkanH_SelectPresentMode(
            m_PhysicalDevice, surface, modes, IM_ARRAYSIZE(modes));

        ImGui_ImplVulkanH_CreateOrResizeWindow(
            m_Instance, m_PhysicalDevice, m_Device, m_WD,
            m_QueueFamily, nullptr, m_Width, m_Height, m_MinImageCount,
            VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT);
        return true;
    }

    void SetupImGuiBackend() {
        ImGui_ImplVulkan_InitInfo ii{};
        ii.Instance = m_Instance;
        ii.PhysicalDevice = m_PhysicalDevice;
        ii.Device = m_Device;
        ii.QueueFamily = m_QueueFamily;
        ii.Queue = m_Queue;
        ii.DescriptorPool = m_DescPool;
        // ImGui renders into the offscreen scene pass when bloom is wired up;
        // otherwise it draws straight into the swapchain.
        ii.PipelineInfoMain.RenderPass = m_Bloom.Ready() ? m_Bloom.GetSceneRenderPass()
                                                        : m_WD->RenderPass;
        ii.PipelineInfoMain.MSAASamples = VK_SAMPLE_COUNT_1_BIT;
        ii.MinImageCount = m_MinImageCount;
        ii.ImageCount = m_WD->ImageCount;
        ii.CheckVkResultFn = check_vk;
        ImGui_ImplVulkan_Init(&ii);
    }

    void RebuildSwapchain() {
        int w = ANativeWindow_getWidth(m_Window);
        int h = ANativeWindow_getHeight(m_Window);
        if (w > 0 && h > 0) {
            usleep(200000);
            ImGui_ImplVulkan_SetMinImageCount(m_MinImageCount);
            ImGui_ImplVulkanH_CreateOrResizeWindow(
                m_Instance, m_PhysicalDevice, m_Device, m_WD,
                m_QueueFamily, nullptr, w, h, m_MinImageCount,
                VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT);
            m_WD->FrameIndex = 0;
            m_Width = w; m_Height = h;

            // Tear down and rebuild bloom against the new dimensions and
            // swapchain render pass. If anything fails we fall back to the
            // direct-to-swapchain path automatically.
            if (m_Bloom.Ready()) {
                m_Bloom.Shutdown();
                if (m_Bloom.Init(m_Device, m_PhysicalDevice, m_DescPool,
                                 m_WD->SurfaceFormat.format, m_Width, m_Height)) {
                    if (!m_Bloom.BindToSwapchainRenderPass(m_WD->RenderPass))
                        m_Bloom.Shutdown();
                    else
                        m_Bloom.RegisterImGuiSnapshot();
                }
            }
        }
        m_SwapChainRebuild = false;
    }

    void Submit(ImDrawData* draw) {
        VkResult err;
        VkSemaphore acq = m_WD->FrameSemaphores[m_WD->SemaphoreIndex].ImageAcquiredSemaphore;
        VkSemaphore done = m_WD->FrameSemaphores[m_WD->SemaphoreIndex].RenderCompleteSemaphore;
        err = vkAcquireNextImageKHR(m_Device, m_WD->Swapchain, UINT64_MAX, acq, VK_NULL_HANDLE, &m_WD->FrameIndex);
        if (err == VK_ERROR_OUT_OF_DATE_KHR) { m_SwapChainRebuild = true; return; }

        ImGui_ImplVulkanH_Frame* fd = &m_WD->Frames[m_WD->FrameIndex];
        vkWaitForFences(m_Device, 1, &fd->Fence, VK_TRUE, UINT64_MAX);
        vkResetFences(m_Device, 1, &fd->Fence);
        vkResetCommandPool(m_Device, fd->CommandPool, 0);

        VkCommandBufferBeginInfo bi{};
        bi.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        vkBeginCommandBuffer(fd->CommandBuffer, &bi);

        if (m_Bloom.Ready()) {
            // ImGui draws into the offscreen scene image, then threshold +
            // separable Gaussian blur populate the bloom image, and the
            // composite pass writes scene + bloom into the swapchain.
            m_Bloom.BeginScene(fd->CommandBuffer);
            ImGui_ImplVulkan_RenderDrawData(draw, fd->CommandBuffer);
            m_Bloom.EndSceneAndBlur(fd->CommandBuffer);

            VkRenderPassBeginInfo rpi{};
            rpi.sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO;
            rpi.renderPass = m_WD->RenderPass;
            rpi.framebuffer = fd->Framebuffer;
            rpi.renderArea.extent.width  = m_WD->Width;
            rpi.renderArea.extent.height = m_WD->Height;
            rpi.clearValueCount = 1;
            rpi.pClearValues = &m_WD->ClearValue;
            vkCmdBeginRenderPass(fd->CommandBuffer, &rpi, VK_SUBPASS_CONTENTS_INLINE);
            m_Bloom.RecordCompositeDraw(fd->CommandBuffer);
            vkCmdEndRenderPass(fd->CommandBuffer);

            // Stash a copy of the just-rendered scene for next frame's
            // shatter chips to sample.
            m_Bloom.RecordSnapshotCopy(fd->CommandBuffer);
        } else {
            VkRenderPassBeginInfo rpi{};
            rpi.sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO;
            rpi.renderPass = m_WD->RenderPass;
            rpi.framebuffer = fd->Framebuffer;
            rpi.renderArea.extent.width  = m_WD->Width;
            rpi.renderArea.extent.height = m_WD->Height;
            rpi.clearValueCount = 1;
            rpi.pClearValues = &m_WD->ClearValue;
            vkCmdBeginRenderPass(fd->CommandBuffer, &rpi, VK_SUBPASS_CONTENTS_INLINE);
            ImGui_ImplVulkan_RenderDrawData(draw, fd->CommandBuffer);
            vkCmdEndRenderPass(fd->CommandBuffer);
        }

        vkEndCommandBuffer(fd->CommandBuffer);

        VkPipelineStageFlags stage = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
        VkSubmitInfo si{};
        si.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
        si.waitSemaphoreCount = 1;
        si.pWaitSemaphores = &acq;
        si.pWaitDstStageMask = &stage;
        si.commandBufferCount = 1;
        si.pCommandBuffers = &fd->CommandBuffer;
        si.signalSemaphoreCount = 1;
        si.pSignalSemaphores = &done;
        vkQueueSubmit(m_Queue, 1, &si, fd->Fence);

        VkPresentInfoKHR pi{};
        pi.sType = VK_STRUCTURE_TYPE_PRESENT_INFO_KHR;
        pi.waitSemaphoreCount = 1;
        pi.pWaitSemaphores = &done;
        pi.swapchainCount = 1;
        pi.pSwapchains = &m_WD->Swapchain;
        pi.pImageIndices = &m_WD->FrameIndex;
        err = vkQueuePresentKHR(m_Queue, &pi);
        if (err == VK_ERROR_OUT_OF_DATE_KHR) { m_SwapChainRebuild = true; return; }
        m_WD->SemaphoreIndex = (m_WD->SemaphoreIndex + 1) % m_WD->SemaphoreCount;
    }

    ANativeWindow* m_Window = nullptr;
    VkInstance m_Instance = VK_NULL_HANDLE;
    VkPhysicalDevice m_PhysicalDevice = VK_NULL_HANDLE;
    VkDevice m_Device = VK_NULL_HANDLE;
    VkQueue m_Queue = VK_NULL_HANDLE;
    VkDescriptorPool m_DescPool = VK_NULL_HANDLE;
    ImGui_ImplVulkanH_Window* m_WD = nullptr;
    uint32_t m_QueueFamily = UINT32_MAX;
    int m_Width = 0;
    int m_Height = 0;
    int m_MinImageCount = 2;
    bool m_SwapChainRebuild = false;
    BloomVK m_Bloom;
};

} // namespace

std::unique_ptr<IRenderer> MakeVKRenderer() {
    return std::unique_ptr<IRenderer>(new VKRenderer());
}

} // namespace aimgui
