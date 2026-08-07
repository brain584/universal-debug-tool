#pragma once

#include "vulkan_wrapper.h"

namespace aimgui {

// Post-process bloom for the Vulkan backend. Layout:
//
//   ImGui draw  --> scene image  (offscreen, full res, SHADER_READ_ONLY after pass)
//   threshold   --> blur image 0 (half res)
//   blur H      --> blur image 1
//   blur V      --> blur image 0
//   composite   --> swapchain image    (caller's render pass)
//
// Usage in renderer_vk.cpp's Submit():
//
//   if (bloom.Ready()) {
//       bloom.BeginScene(cmd);
//       ImGui_ImplVulkan_RenderDrawData(...);
//       bloom.EndSceneAndBlur(cmd);
//       vkCmdBeginRenderPass(cmd, swapchain_rp, swapchain_fb, ...);
//       bloom.RecordCompositeDraw(cmd);
//       vkCmdEndRenderPass(cmd);
//   } else {
//       // fallback: ImGui pipeline must have been initialised with swapchain RP
//       vkCmdBeginRenderPass(cmd, swapchain_rp, swapchain_fb, ...);
//       ImGui_ImplVulkan_RenderDrawData(...);
//       vkCmdEndRenderPass(cmd);
//   }
//
// The render pass used by ImGui (via GetSceneRenderPass()) is set up to
// transition the scene image to SHADER_READ_ONLY_OPTIMAL at end-of-pass so
// no manual barrier is required around ImGui's draw call.
class BloomVK {
public:
    bool Init(VkDevice device,
              VkPhysicalDevice phys,
              VkDescriptorPool descPool,
              VkFormat colorFormat,
              uint32_t width,
              uint32_t height);

    void Shutdown();
    bool Ready() const { return m_Ready; }

    void SetIntensity(float i) { m_Intensity = i; }
    void SetSnapshotFrozen(bool frozen) { m_SnapshotFrozen = frozen; }

    VkRenderPass GetSceneRenderPass() const { return m_SceneRP; }

    // Records the bloom composite pipeline. Caller must have an active
    // render pass whose attachment format matches the swapchain.
    bool BindToSwapchainRenderPass(VkRenderPass swapchainRP);

    // Registers a sampleable snapshot of the scene image with ImGui's
    // descriptor pool so shatter chips can read prev-frame UI as a
    // texture. Must be called after ImGui_ImplVulkan_Init.
    void RegisterImGuiSnapshot();

    // Opaque handle suitable for casting to ImTextureID. Returns VK_NULL_HANDLE
    // if RegisterImGuiSnapshot wasn't called or failed.
    VkDescriptorSet GetSnapshotDescriptorSet() const { return m_PrevSceneImGuiDS; }

    void BeginScene(VkCommandBuffer cmd);
    void EndSceneAndBlur(VkCommandBuffer cmd);
    void RecordCompositeDraw(VkCommandBuffer cmd);

    // Copy scene image → prev-scene image at the very end of the command
    // buffer, so next frame's shatter chips have a fresh snapshot.
    void RecordSnapshotCopy(VkCommandBuffer cmd);

private:
    bool             m_Ready  = false;
    VkDevice         m_Device = VK_NULL_HANDLE;
    VkPhysicalDevice m_Phys   = VK_NULL_HANDLE;
    VkDescriptorPool m_Pool   = VK_NULL_HANDLE;
    VkFormat         m_Format = VK_FORMAT_UNDEFINED;
    uint32_t         m_W = 0, m_H = 0;
    uint32_t         m_BW = 0, m_BH = 0;
    float            m_Intensity      = 0.75f;
    bool             m_SnapshotFrozen = false;

    VkRenderPass     m_SceneRP = VK_NULL_HANDLE;
    VkRenderPass     m_BlurRP  = VK_NULL_HANDLE;

    VkImage          m_SceneImage = VK_NULL_HANDLE;
    VkImageView      m_SceneView  = VK_NULL_HANDLE;
    VkDeviceMemory   m_SceneMem   = VK_NULL_HANDLE;
    VkFramebuffer    m_SceneFB    = VK_NULL_HANDLE;

    // Snapshot of the previous frame's scene, sampled by ImGui-issued
    // shatter chip draws. Owned VkImage + view, plus a VkDescriptorSet
    // borrowed from imgui's pool so we can hand its handle out as an
    // ImTextureID.
    VkImage          m_PrevSceneImage    = VK_NULL_HANDLE;
    VkImageView      m_PrevSceneView     = VK_NULL_HANDLE;
    VkDeviceMemory   m_PrevSceneMem      = VK_NULL_HANDLE;
    VkDescriptorSet  m_PrevSceneImGuiDS  = VK_NULL_HANDLE;
    bool             m_PrevSceneFirstUse = true;

    VkImage          m_BlurImage[2]{};
    VkImageView      m_BlurView[2]{};
    VkDeviceMemory   m_BlurMem[2]{};
    VkFramebuffer    m_BlurFB[2]{};

    VkSampler                m_Sampler          = VK_NULL_HANDLE;
    VkDescriptorSetLayout    m_DSL1             = VK_NULL_HANDLE;
    VkDescriptorSetLayout    m_DSL2             = VK_NULL_HANDLE;
    VkPipelineLayout         m_PLA              = VK_NULL_HANDLE;
    VkPipelineLayout         m_PLB              = VK_NULL_HANDLE;

    VkShaderModule           m_VS               = VK_NULL_HANDLE;
    VkShaderModule           m_FSThresh         = VK_NULL_HANDLE;
    VkShaderModule           m_FSBlur           = VK_NULL_HANDLE;
    VkShaderModule           m_FSComp           = VK_NULL_HANDLE;

    VkPipeline               m_PipeThresh       = VK_NULL_HANDLE;
    VkPipeline               m_PipeBlur         = VK_NULL_HANDLE;
    VkPipeline               m_PipeComp         = VK_NULL_HANDLE;

    VkDescriptorSet          m_DSThresh         = VK_NULL_HANDLE;
    VkDescriptorSet          m_DSBlurH          = VK_NULL_HANDLE;
    VkDescriptorSet          m_DSBlurV          = VK_NULL_HANDLE;
    VkDescriptorSet          m_DSComp           = VK_NULL_HANDLE;
};

} // namespace aimgui
