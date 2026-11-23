"""
Zero-Dependency Vulkan 1.x Compute Runner via ctypes C-ABI (Alpha-C92).

Loads `vulkan-1.dll` / `libvulkan.so.1` / `libvulkan.1.dylib` (`libMoltenVK.dylib`) directly
and executes binary Khronos SPIR-V compute shaders over two host-visible SSBO buffers
(`DescriptorSet=0, Binding=0` inputs -> `DescriptorSet=0, Binding=1` outputs) using
real `vkCreateInstance` -> `vkCreateDevice` -> `vkCreateComputePipelines` -> `vkCmdDispatch`.
"""

import ctypes
import os
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple


# Vulkan Constants
VK_SUCCESS = 0
VK_API_VERSION_1_2 = (1 << 22) | (2 << 12)
VK_QUEUE_COMPUTE_BIT = 0x00000002
VK_SHADER_STAGE_COMPUTE_BIT = 0x00000020
VK_DESCRIPTOR_TYPE_STORAGE_BUFFER = 7
VK_BUFFER_USAGE_STORAGE_BUFFER_BIT = 0x00000020
VK_SHARING_MODE_EXCLUSIVE = 0
VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT = 0x00000002
VK_MEMORY_PROPERTY_HOST_COHERENT_BIT = 0x00000004
VK_COMMAND_BUFFER_LEVEL_PRIMARY = 0
VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT = 0x00000001
VK_WHOLE_SIZE = 0xFFFFFFFFFFFFFFFF

VK_STRUCTURE_TYPE_APPLICATION_INFO = 0
VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO = 1
VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO = 2
VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO = 3
VK_STRUCTURE_TYPE_SUBMIT_INFO = 4
VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO = 5
VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO = 12
VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO = 16
VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO = 18
VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO = 29
VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO = 30
VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO = 32
VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO = 33
VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO = 34
VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET = 35
VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO = 39
VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO = 40
VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO = 42


class VkApplicationInfo(ctypes.Structure):
    _fields_ = [
        ("sType", ctypes.c_uint32),
        ("pNext", ctypes.c_void_p),
        ("pApplicationName", ctypes.c_char_p),
        ("applicationVersion", ctypes.c_uint32),
        ("pEngineName", ctypes.c_char_p),
        ("engineVersion", ctypes.c_uint32),
        ("apiVersion", ctypes.c_uint32),
    ]


class VkInstanceCreateInfo(ctypes.Structure):
    _fields_ = [
        ("sType", ctypes.c_uint32),
        ("pNext", ctypes.c_void_p),
        ("flags", ctypes.c_uint32),
        ("pApplicationInfo", ctypes.POINTER(VkApplicationInfo)),
        ("enabledLayerCount", ctypes.c_uint32),
        ("ppEnabledLayerNames", ctypes.POINTER(ctypes.c_char_p)),
        ("enabledExtensionCount", ctypes.c_uint32),
        ("ppEnabledExtensionNames", ctypes.POINTER(ctypes.c_char_p)),
    ]


class VkExtent3D(ctypes.Structure):
    _fields_ = [("width", ctypes.c_uint32), ("height", ctypes.c_uint32), ("depth", ctypes.c_uint32)]


class VkQueueFamilyProperties(ctypes.Structure):
    _fields_ = [
        ("queueFlags", ctypes.c_uint32),
        ("queueCount", ctypes.c_uint32),
        ("timestampValidBits", ctypes.c_uint32),
        ("minImageTransferGranularity", VkExtent3D),
    ]


class VkMemoryType(ctypes.Structure):
    _fields_ = [("propertyFlags", ctypes.c_uint32), ("heapIndex", ctypes.c_uint32)]


class VkMemoryHeap(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint64), ("flags", ctypes.c_uint32)]


class VkPhysicalDeviceMemoryProperties(ctypes.Structure):
    _fields_ = [
        ("memoryTypeCount", ctypes.c_uint32),
        ("memoryTypes", VkMemoryType * 32),
        ("memoryHeapCount", ctypes.c_uint32),
        ("memoryHeaps", VkMemoryHeap * 16),
    ]


class VkPhysicalDeviceFeatures(ctypes.Structure):
    _fields_ = [("features", ctypes.c_uint32 * 55)]


class VkPhysicalDeviceProperties(ctypes.Structure):
    _fields_ = [("raw", ctypes.c_uint8 * 1024)]


class VkDeviceQueueCreateInfo(ctypes.Structure):
    _fields_ = [
        ("sType", ctypes.c_uint32),
        ("pNext", ctypes.c_void_p),
        ("flags", ctypes.c_uint32),
        ("queueFamilyIndex", ctypes.c_uint32),
        ("queueCount", ctypes.c_uint32),
        ("pQueuePriorities", ctypes.POINTER(ctypes.c_float)),
    ]


class VkDeviceCreateInfo(ctypes.Structure):
    _fields_ = [
        ("sType", ctypes.c_uint32),
        ("pNext", ctypes.c_void_p),
        ("flags", ctypes.c_uint32),
        ("queueCreateInfoCount", ctypes.c_uint32),
        ("pQueueCreateInfos", ctypes.POINTER(VkDeviceQueueCreateInfo)),
        ("enabledLayerCount", ctypes.c_uint32),
        ("ppEnabledLayerNames", ctypes.POINTER(ctypes.c_char_p)),
        ("enabledExtensionCount", ctypes.c_uint32),
        ("ppEnabledExtensionNames", ctypes.POINTER(ctypes.c_char_p)),
        ("pEnabledFeatures", ctypes.POINTER(VkPhysicalDeviceFeatures)),
    ]


class VkBufferCreateInfo(ctypes.Structure):
    _fields_ = [
        ("sType", ctypes.c_uint32),
        ("pNext", ctypes.c_void_p),
        ("flags", ctypes.c_uint32),
        ("size", ctypes.c_uint64),
        ("usage", ctypes.c_uint32),
        ("sharingMode", ctypes.c_uint32),
        ("queueFamilyIndexCount", ctypes.c_uint32),
        ("pQueueFamilyIndices", ctypes.POINTER(ctypes.c_uint32)),
    ]


class VkMemoryRequirements(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_uint64),
        ("alignment", ctypes.c_uint64),
        ("memoryTypeBits", ctypes.c_uint32),
    ]


class VkMemoryAllocateInfo(ctypes.Structure):
    _fields_ = [
        ("sType", ctypes.c_uint32),
        ("pNext", ctypes.c_void_p),
        ("allocationSize", ctypes.c_uint64),
        ("memoryTypeIndex", ctypes.c_uint32),
    ]


class VkShaderModuleCreateInfo(ctypes.Structure):
    _fields_ = [
        ("sType", ctypes.c_uint32),
        ("pNext", ctypes.c_void_p),
        ("flags", ctypes.c_uint32),
        ("codeSize", ctypes.c_size_t),
        ("pCode", ctypes.POINTER(ctypes.c_uint32)),
    ]


class VkDescriptorSetLayoutBinding(ctypes.Structure):
    _fields_ = [
        ("binding", ctypes.c_uint32),
        ("descriptorType", ctypes.c_uint32),
        ("descriptorCount", ctypes.c_uint32),
        ("stageFlags", ctypes.c_uint32),
        ("pImmutableSamplers", ctypes.c_void_p),
    ]


class VkDescriptorSetLayoutCreateInfo(ctypes.Structure):
    _fields_ = [
        ("sType", ctypes.c_uint32),
        ("pNext", ctypes.c_void_p),
        ("flags", ctypes.c_uint32),
        ("bindingCount", ctypes.c_uint32),
        ("pBindings", ctypes.POINTER(VkDescriptorSetLayoutBinding)),
    ]


class VkPipelineLayoutCreateInfo(ctypes.Structure):
    _fields_ = [
        ("sType", ctypes.c_uint32),
        ("pNext", ctypes.c_void_p),
        ("flags", ctypes.c_uint32),
        ("setLayoutCount", ctypes.c_uint32),
        ("pSetLayouts", ctypes.POINTER(ctypes.c_uint64)),
        ("pushConstantRangeCount", ctypes.c_uint32),
        ("pPushConstantRanges", ctypes.c_void_p),
    ]


class VkPipelineShaderStageCreateInfo(ctypes.Structure):
    _fields_ = [
        ("sType", ctypes.c_uint32),
        ("pNext", ctypes.c_void_p),
        ("flags", ctypes.c_uint32),
        ("stage", ctypes.c_uint32),
        ("module", ctypes.c_uint64),
        ("pName", ctypes.c_char_p),
        ("pSpecializationInfo", ctypes.c_void_p),
    ]


class VkComputePipelineCreateInfo(ctypes.Structure):
    _fields_ = [
        ("sType", ctypes.c_uint32),
        ("pNext", ctypes.c_void_p),
        ("flags", ctypes.c_uint32),
        ("stage", VkPipelineShaderStageCreateInfo),
        ("layout", ctypes.c_uint64),
        ("basePipelineHandle", ctypes.c_uint64),
        ("basePipelineIndex", ctypes.c_int32),
    ]


class VkDescriptorPoolSize(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint32), ("descriptorCount", ctypes.c_uint32)]


class VkDescriptorPoolCreateInfo(ctypes.Structure):
    _fields_ = [
        ("sType", ctypes.c_uint32),
        ("pNext", ctypes.c_void_p),
        ("flags", ctypes.c_uint32),
        ("maxSets", ctypes.c_uint32),
        ("poolSizeCount", ctypes.c_uint32),
        ("pPoolSizes", ctypes.POINTER(VkDescriptorPoolSize)),
    ]


class VkDescriptorSetAllocateInfo(ctypes.Structure):
    _fields_ = [
        ("sType", ctypes.c_uint32),
        ("pNext", ctypes.c_void_p),
        ("descriptorPool", ctypes.c_uint64),
        ("descriptorSetCount", ctypes.c_uint32),
        ("pSetLayouts", ctypes.POINTER(ctypes.c_uint64)),
    ]


class VkDescriptorBufferInfo(ctypes.Structure):
    _fields_ = [("buffer", ctypes.c_uint64), ("offset", ctypes.c_uint64), ("range", ctypes.c_uint64)]


class VkWriteDescriptorSet(ctypes.Structure):
    _fields_ = [
        ("sType", ctypes.c_uint32),
        ("pNext", ctypes.c_void_p),
        ("dstSet", ctypes.c_uint64),
        ("dstBinding", ctypes.c_uint32),
        ("dstArrayElement", ctypes.c_uint32),
        ("descriptorCount", ctypes.c_uint32),
        ("descriptorType", ctypes.c_uint32),
        ("pImageInfo", ctypes.c_void_p),
        ("pBufferInfo", ctypes.POINTER(VkDescriptorBufferInfo)),
        ("pTexelBufferView", ctypes.c_void_p),
    ]


class VkCommandPoolCreateInfo(ctypes.Structure):
    _fields_ = [
        ("sType", ctypes.c_uint32),
        ("pNext", ctypes.c_void_p),
        ("flags", ctypes.c_uint32),
        ("queueFamilyIndex", ctypes.c_uint32),
    ]


class VkCommandBufferAllocateInfo(ctypes.Structure):
    _fields_ = [
        ("sType", ctypes.c_uint32),
        ("pNext", ctypes.c_void_p),
        ("commandPool", ctypes.c_uint64),
        ("level", ctypes.c_uint32),
        ("commandBufferCount", ctypes.c_uint32),
    ]


class VkCommandBufferBeginInfo(ctypes.Structure):
    _fields_ = [
        ("sType", ctypes.c_uint32),
        ("pNext", ctypes.c_void_p),
        ("flags", ctypes.c_uint32),
        ("pInheritanceInfo", ctypes.c_void_p),
    ]


class VkSubmitInfo(ctypes.Structure):
    _fields_ = [
        ("sType", ctypes.c_uint32),
        ("pNext", ctypes.c_void_p),
        ("waitSemaphoreCount", ctypes.c_uint32),
        ("pWaitSemaphores", ctypes.c_void_p),
        ("pWaitDstStageMask", ctypes.c_void_p),
        ("commandBufferCount", ctypes.c_uint32),
        ("pCommandBuffers", ctypes.POINTER(ctypes.c_void_p)),
        ("signalSemaphoreCount", ctypes.c_uint32),
        ("pSignalSemaphores", ctypes.c_void_p),
    ]


def _load_vulkan_library() -> Optional[ctypes.CDLL]:
    candidates = (
        ["vulkan-1.dll"]
        if sys.platform == "win32"
        else (
            ["libvulkan.1.dylib", "libMoltenVK.dylib", "/opt/homebrew/lib/libvulkan.1.dylib"]
            if sys.platform == "darwin"
            else ["libvulkan.so.1", "libvulkan.so"]
        )
    )
    for name in candidates:
        try:
            return ctypes.CDLL(name)
        except OSError:
            continue
    return None


def _bind_vk_protos(vk: ctypes.CDLL) -> None:
    vk.vkCreateInstance.argtypes = [ctypes.POINTER(VkInstanceCreateInfo), ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    vk.vkCreateInstance.restype = ctypes.c_int32
    vk.vkDestroyInstance.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    vk.vkEnumeratePhysicalDevices.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_void_p)]
    vk.vkEnumeratePhysicalDevices.restype = ctypes.c_int32
    vk.vkGetPhysicalDeviceProperties.argtypes = [ctypes.c_void_p, ctypes.POINTER(VkPhysicalDeviceProperties)]
    vk.vkGetPhysicalDeviceFeatures.argtypes = [ctypes.c_void_p, ctypes.POINTER(VkPhysicalDeviceFeatures)]
    vk.vkGetPhysicalDeviceMemoryProperties.argtypes = [ctypes.c_void_p, ctypes.POINTER(VkPhysicalDeviceMemoryProperties)]
    vk.vkGetPhysicalDeviceQueueFamilyProperties.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(VkQueueFamilyProperties)]
    vk.vkCreateDevice.argtypes = [ctypes.c_void_p, ctypes.POINTER(VkDeviceCreateInfo), ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    vk.vkCreateDevice.restype = ctypes.c_int32
    vk.vkDestroyDevice.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    vk.vkGetDeviceQueue.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
    vk.vkCreateShaderModule.argtypes = [ctypes.c_void_p, ctypes.POINTER(VkShaderModuleCreateInfo), ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64)]
    vk.vkCreateShaderModule.restype = ctypes.c_int32
    vk.vkDestroyShaderModule.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p]
    vk.vkCreateDescriptorSetLayout.argtypes = [ctypes.c_void_p, ctypes.POINTER(VkDescriptorSetLayoutCreateInfo), ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64)]
    vk.vkCreateDescriptorSetLayout.restype = ctypes.c_int32
    vk.vkDestroyDescriptorSetLayout.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p]
    vk.vkCreatePipelineLayout.argtypes = [ctypes.c_void_p, ctypes.POINTER(VkPipelineLayoutCreateInfo), ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64)]
    vk.vkCreatePipelineLayout.restype = ctypes.c_int32
    vk.vkDestroyPipelineLayout.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p]
    vk.vkCreateComputePipelines.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32, ctypes.POINTER(VkComputePipelineCreateInfo), ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64)]
    vk.vkCreateComputePipelines.restype = ctypes.c_int32
    vk.vkDestroyPipeline.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p]
    vk.vkCreateBuffer.argtypes = [ctypes.c_void_p, ctypes.POINTER(VkBufferCreateInfo), ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64)]
    vk.vkCreateBuffer.restype = ctypes.c_int32
    vk.vkDestroyBuffer.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p]
    vk.vkGetBufferMemoryRequirements.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.POINTER(VkMemoryRequirements)]
    vk.vkAllocateMemory.argtypes = [ctypes.c_void_p, ctypes.POINTER(VkMemoryAllocateInfo), ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64)]
    vk.vkAllocateMemory.restype = ctypes.c_int32
    vk.vkFreeMemory.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p]
    vk.vkBindBufferMemory.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
    vk.vkBindBufferMemory.restype = ctypes.c_int32
    vk.vkMapMemory.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
    vk.vkMapMemory.restype = ctypes.c_int32
    vk.vkUnmapMemory.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
    vk.vkCreateDescriptorPool.argtypes = [ctypes.c_void_p, ctypes.POINTER(VkDescriptorPoolCreateInfo), ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64)]
    vk.vkCreateDescriptorPool.restype = ctypes.c_int32
    vk.vkDestroyDescriptorPool.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p]
    vk.vkAllocateDescriptorSets.argtypes = [ctypes.c_void_p, ctypes.POINTER(VkDescriptorSetAllocateInfo), ctypes.POINTER(ctypes.c_uint64)]
    vk.vkAllocateDescriptorSets.restype = ctypes.c_int32
    vk.vkUpdateDescriptorSets.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(VkWriteDescriptorSet), ctypes.c_uint32, ctypes.c_void_p]
    vk.vkCreateCommandPool.argtypes = [ctypes.c_void_p, ctypes.POINTER(VkCommandPoolCreateInfo), ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64)]
    vk.vkCreateCommandPool.restype = ctypes.c_int32
    vk.vkDestroyCommandPool.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p]
    vk.vkAllocateCommandBuffers.argtypes = [ctypes.c_void_p, ctypes.POINTER(VkCommandBufferAllocateInfo), ctypes.POINTER(ctypes.c_void_p)]
    vk.vkAllocateCommandBuffers.restype = ctypes.c_int32
    vk.vkBeginCommandBuffer.argtypes = [ctypes.c_void_p, ctypes.POINTER(VkCommandBufferBeginInfo)]
    vk.vkBeginCommandBuffer.restype = ctypes.c_int32
    vk.vkEndCommandBuffer.argtypes = [ctypes.c_void_p]
    vk.vkEndCommandBuffer.restype = ctypes.c_int32
    vk.vkCmdBindPipeline.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint64]
    vk.vkCmdBindDescriptorSets.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint64), ctypes.c_uint32, ctypes.c_void_p]
    vk.vkCmdDispatch.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
    vk.vkQueueSubmit.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(VkSubmitInfo), ctypes.c_uint64]
    vk.vkQueueSubmit.restype = ctypes.c_int32
    vk.vkQueueWaitIdle.argtypes = [ctypes.c_void_p]
    vk.vkQueueWaitIdle.restype = ctypes.c_int32


def is_vulkan_device_available() -> Dict[str, Any]:
    """Probes whether a Vulkan ICD + physical compute device with shaderInt64 is present."""
    vk = _load_vulkan_library()
    if vk is None:
        return {"available": False, "reason": "VULKAN_LOADER_NOT_FOUND"}
    _bind_vk_protos(vk)
    app_info = VkApplicationInfo(
        sType=VK_STRUCTURE_TYPE_APPLICATION_INFO,
        pApplicationName=b"OmniCompilerProbe",
        applicationVersion=1,
        pEngineName=b"Omni",
        engineVersion=1,
        apiVersion=VK_API_VERSION_1_2,
    )
    inst_info = VkInstanceCreateInfo(
        sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
        pApplicationInfo=ctypes.pointer(app_info),
    )
    instance = ctypes.c_void_p()
    rc = vk.vkCreateInstance(ctypes.byref(inst_info), None, ctypes.byref(instance))
    if rc != VK_SUCCESS or not instance.value:
        return {"available": False, "reason": f"VK_CREATE_INSTANCE_ERR_{rc}"}
    try:
        cnt = ctypes.c_uint32(0)
        vk.vkEnumeratePhysicalDevices(instance, ctypes.byref(cnt), None)
        if cnt.value == 0:
            return {"available": False, "reason": "NO_PHYSICAL_DEVICES"}
        devs = (ctypes.c_void_p * cnt.value)()
        vk.vkEnumeratePhysicalDevices(instance, ctypes.byref(cnt), devs)
        phys = devs[0]
        props = VkPhysicalDeviceProperties()
        vk.vkGetPhysicalDeviceProperties(phys, ctypes.byref(props))
        raw = bytes(props.raw)
        dev_name = raw[20:276].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        feats = VkPhysicalDeviceFeatures()
        vk.vkGetPhysicalDeviceFeatures(phys, ctypes.byref(feats))
        has_i64 = bool(feats.features[45])
        return {"available": True, "device_count": cnt.value, "device_name": dev_name, "shader_int64": has_i64}
    finally:
        vk.vkDestroyInstance(instance, None)


def run_vulkan_compute_shader(
    spirv_bytes: bytes,
    inputs_i64: List[int],
    local_size_x: int = 64,
) -> Dict[str, Any]:
    """
    Executes a Vulkan compute shader taking `inputs_i64` in DescriptorSet=0 Binding=0
    and returning computed `int64` results from DescriptorSet=0 Binding=1.
    """
    if not inputs_i64:
        return {"executed": True, "outputs": [], "device_name": ""}
    if (len(spirv_bytes) % 4) != 0:
        raise ValueError("SPIR-V binary must be 4-byte aligned")

    vk = _load_vulkan_library()
    if vk is None:
        raise RuntimeError("Vulkan loader library not available on this OS")
    _bind_vk_protos(vk)

    app_info = VkApplicationInfo(
        sType=VK_STRUCTURE_TYPE_APPLICATION_INFO,
        pApplicationName=b"OmniCompilerVulkanCompute",
        applicationVersion=1,
        pEngineName=b"OmniCompiler",
        engineVersion=1,
        apiVersion=VK_API_VERSION_1_2,
    )
    inst_info = VkInstanceCreateInfo(
        sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
        pApplicationInfo=ctypes.pointer(app_info),
    )
    instance = ctypes.c_void_p()
    rc = vk.vkCreateInstance(ctypes.byref(inst_info), None, ctypes.byref(instance))
    if rc != VK_SUCCESS:
        raise RuntimeError(f"vkCreateInstance failed with code {rc}")

    device = ctypes.c_void_p()
    shader_mod = ctypes.c_uint64(0)
    set_layout = ctypes.c_uint64(0)
    pipe_layout = ctypes.c_uint64(0)
    pipeline = ctypes.c_uint64(0)
    desc_pool = ctypes.c_uint64(0)
    cmd_pool = ctypes.c_uint64(0)
    in_buf = ctypes.c_uint64(0)
    out_buf = ctypes.c_uint64(0)
    in_mem = ctypes.c_uint64(0)
    out_mem = ctypes.c_uint64(0)

    try:
        cnt = ctypes.c_uint32(0)
        vk.vkEnumeratePhysicalDevices(instance, ctypes.byref(cnt), None)
        if cnt.value == 0:
            raise RuntimeError("No Vulkan physical devices available")
        devs = (ctypes.c_void_p * cnt.value)()
        vk.vkEnumeratePhysicalDevices(instance, ctypes.byref(cnt), devs)

        # Pick physical device supporting compute queue + shaderInt64
        chosen_phys = None
        chosen_q_idx = 0
        chosen_name = "Unknown"
        chosen_feats = VkPhysicalDeviceFeatures()
        for idx_d in range(cnt.value):
            p = devs[idx_d]
            feats = VkPhysicalDeviceFeatures()
            vk.vkGetPhysicalDeviceFeatures(p, ctypes.byref(feats))
            qcnt = ctypes.c_uint32(0)
            vk.vkGetPhysicalDeviceQueueFamilyProperties(p, ctypes.byref(qcnt), None)
            qprops = (VkQueueFamilyProperties * qcnt.value)()
            vk.vkGetPhysicalDeviceQueueFamilyProperties(p, ctypes.byref(qcnt), qprops)
            for qi in range(qcnt.value):
                if (qprops[qi].queueFlags & VK_QUEUE_COMPUTE_BIT) != 0:
                    props = VkPhysicalDeviceProperties()
                    vk.vkGetPhysicalDeviceProperties(p, ctypes.byref(props))
                    dname = bytes(props.raw)[20:276].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                    if chosen_phys is None or feats.features[45]:
                        chosen_phys = p
                        chosen_q_idx = qi
                        chosen_name = dname
                        chosen_feats = feats
                    if feats.features[45]:
                        break
            if chosen_phys is not None and chosen_feats.features[45]:
                break

        if chosen_phys is None:
            raise RuntimeError("No Vulkan compute-capable queue family found")

        prio = (ctypes.c_float * 1)(1.0)
        qinfo = VkDeviceQueueCreateInfo(
            sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
            queueFamilyIndex=chosen_q_idx,
            queueCount=1,
            pQueuePriorities=prio,
        )
        dinfo = VkDeviceCreateInfo(
            sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
            queueCreateInfoCount=1,
            pQueueCreateInfos=ctypes.pointer(qinfo),
            pEnabledFeatures=ctypes.pointer(chosen_feats),
        )
        rc = vk.vkCreateDevice(chosen_phys, ctypes.byref(dinfo), None, ctypes.byref(device))
        if rc != VK_SUCCESS:
            raise RuntimeError(f"vkCreateDevice failed: {rc}")

        queue = ctypes.c_void_p()
        vk.vkGetDeviceQueue(device, chosen_q_idx, 0, ctypes.byref(queue))

        # Memory helper
        mem_props = VkPhysicalDeviceMemoryProperties()
        vk.vkGetPhysicalDeviceMemoryProperties(chosen_phys, ctypes.byref(mem_props))

        def find_mem_type(type_bits: int, req_flags: int) -> int:
            for i in range(mem_props.memoryTypeCount):
                if (type_bits & (1 << i)) and ((mem_props.memoryTypes[i].propertyFlags & req_flags) == req_flags):
                    return i
            raise RuntimeError("No matching HOST_VISIBLE|HOST_COHERENT Vulkan memory type")

        byte_size = len(inputs_i64) * 8

        def create_ssbo() -> Tuple[ctypes.c_uint64, ctypes.c_uint64]:
            binfo = VkBufferCreateInfo(
                sType=VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
                size=byte_size,
                usage=VK_BUFFER_USAGE_STORAGE_BUFFER_BIT,
                sharingMode=VK_SHARING_MODE_EXCLUSIVE,
            )
            buf_h = ctypes.c_uint64(0)
            if vk.vkCreateBuffer(device, ctypes.byref(binfo), None, ctypes.byref(buf_h)) != VK_SUCCESS:
                raise RuntimeError("vkCreateBuffer failed")
            reqs = VkMemoryRequirements()
            vk.vkGetBufferMemoryRequirements(device, buf_h, ctypes.byref(reqs))
            mtype = find_mem_type(
                reqs.memoryTypeBits,
                VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
            )
            minfo = VkMemoryAllocateInfo(
                sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
                allocationSize=reqs.size,
                memoryTypeIndex=mtype,
            )
            mem_h = ctypes.c_uint64(0)
            if vk.vkAllocateMemory(device, ctypes.byref(minfo), None, ctypes.byref(mem_h)) != VK_SUCCESS:
                vk.vkDestroyBuffer(device, buf_h, None)
                raise RuntimeError("vkAllocateMemory failed")
            if vk.vkBindBufferMemory(device, buf_h, mem_h, 0) != VK_SUCCESS:
                vk.vkFreeMemory(device, mem_h, None)
                vk.vkDestroyBuffer(device, buf_h, None)
                raise RuntimeError("vkBindBufferMemory failed")
            return buf_h, mem_h

        in_buf, in_mem = create_ssbo()
        out_buf, out_mem = create_ssbo()

        # Upload inputs
        mapped = ctypes.c_void_p()
        if vk.vkMapMemory(device, in_mem, 0, byte_size, 0, ctypes.byref(mapped)) != VK_SUCCESS:
            raise RuntimeError("vkMapMemory failed for input buffer")
        packed_in = struct.pack(f"<{len(inputs_i64)}q", *[int(v) for v in inputs_i64])
        ctypes.memmove(mapped.value, packed_in, byte_size)
        vk.vkUnmapMemory(device, in_mem)

        # Shader module
        n_words = len(spirv_bytes) // 4
        spv_arr = (ctypes.c_uint32 * n_words).from_buffer_copy(spirv_bytes)
        sinfo = VkShaderModuleCreateInfo(
            sType=VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO,
            codeSize=len(spirv_bytes),
            pCode=spv_arr,
        )
        if vk.vkCreateShaderModule(device, ctypes.byref(sinfo), None, ctypes.byref(shader_mod)) != VK_SUCCESS:
            raise RuntimeError("vkCreateShaderModule failed")

        # Descriptor set layout & compute pipeline
        bindings = (VkDescriptorSetLayoutBinding * 2)(
            VkDescriptorSetLayoutBinding(binding=0, descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, descriptorCount=1, stageFlags=VK_SHADER_STAGE_COMPUTE_BIT),
            VkDescriptorSetLayoutBinding(binding=1, descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, descriptorCount=1, stageFlags=VK_SHADER_STAGE_COMPUTE_BIT),
        )
        dsl_info = VkDescriptorSetLayoutCreateInfo(
            sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO,
            bindingCount=2,
            pBindings=bindings,
        )
        if vk.vkCreateDescriptorSetLayout(device, ctypes.byref(dsl_info), None, ctypes.byref(set_layout)) != VK_SUCCESS:
            raise RuntimeError("vkCreateDescriptorSetLayout failed")

        pl_info = VkPipelineLayoutCreateInfo(
            sType=VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO,
            setLayoutCount=1,
            pSetLayouts=ctypes.pointer(set_layout),
        )
        if vk.vkCreatePipelineLayout(device, ctypes.byref(pl_info), None, ctypes.byref(pipe_layout)) != VK_SUCCESS:
            raise RuntimeError("vkCreatePipelineLayout failed")

        stage_info = VkPipelineShaderStageCreateInfo(
            sType=VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO,
            stage=VK_SHADER_STAGE_COMPUTE_BIT,
            module=shader_mod,
            pName=b"main",
        )
        cp_info = VkComputePipelineCreateInfo(
            sType=VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO,
            stage=stage_info,
            layout=pipe_layout,
            basePipelineIndex=-1,
        )
        if vk.vkCreateComputePipelines(device, 0, 1, ctypes.byref(cp_info), None, ctypes.byref(pipeline)) != VK_SUCCESS:
            raise RuntimeError("vkCreateComputePipelines failed")

        # Descriptor pool & sets
        psize = VkDescriptorPoolSize(type=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, descriptorCount=2)
        dp_info = VkDescriptorPoolCreateInfo(
            sType=VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO,
            maxSets=1,
            poolSizeCount=1,
            pPoolSizes=ctypes.pointer(psize),
        )
        if vk.vkCreateDescriptorPool(device, ctypes.byref(dp_info), None, ctypes.byref(desc_pool)) != VK_SUCCESS:
            raise RuntimeError("vkCreateDescriptorPool failed")

        ds_alloc = VkDescriptorSetAllocateInfo(
            sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO,
            descriptorPool=desc_pool,
            descriptorSetCount=1,
            pSetLayouts=ctypes.pointer(set_layout),
        )
        desc_set = ctypes.c_uint64(0)
        if vk.vkAllocateDescriptorSets(device, ctypes.byref(ds_alloc), ctypes.byref(desc_set)) != VK_SUCCESS:
            raise RuntimeError("vkAllocateDescriptorSets failed")

        binfo0 = VkDescriptorBufferInfo(buffer=in_buf, offset=0, range=VK_WHOLE_SIZE)
        binfo1 = VkDescriptorBufferInfo(buffer=out_buf, offset=0, range=VK_WHOLE_SIZE)
        writes = (VkWriteDescriptorSet * 2)(
            VkWriteDescriptorSet(
                sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
                dstSet=desc_set, dstBinding=0, descriptorCount=1,
                descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
                pBufferInfo=ctypes.pointer(binfo0),
            ),
            VkWriteDescriptorSet(
                sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
                dstSet=desc_set, dstBinding=1, descriptorCount=1,
                descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
                pBufferInfo=ctypes.pointer(binfo1),
            ),
        )
        vk.vkUpdateDescriptorSets(device, 2, writes, 0, None)

        # Command buffer & dispatch
        cpool_info = VkCommandPoolCreateInfo(
            sType=VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
            queueFamilyIndex=chosen_q_idx,
        )
        if vk.vkCreateCommandPool(device, ctypes.byref(cpool_info), None, ctypes.byref(cmd_pool)) != VK_SUCCESS:
            raise RuntimeError("vkCreateCommandPool failed")

        cb_alloc = VkCommandBufferAllocateInfo(
            sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
            commandPool=cmd_pool,
            level=VK_COMMAND_BUFFER_LEVEL_PRIMARY,
            commandBufferCount=1,
        )
        cmd_buf = ctypes.c_void_p()
        if vk.vkAllocateCommandBuffers(device, ctypes.byref(cb_alloc), ctypes.byref(cmd_buf)) != VK_SUCCESS:
            raise RuntimeError("vkAllocateCommandBuffers failed")

        begin_info = VkCommandBufferBeginInfo(
            sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
            flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT,
        )
        vk.vkBeginCommandBuffer(cmd_buf, ctypes.byref(begin_info))
        vk.vkCmdBindPipeline(cmd_buf, 1, pipeline)  # VK_PIPELINE_BIND_POINT_COMPUTE = 1
        vk.vkCmdBindDescriptorSets(cmd_buf, 1, pipe_layout, 0, 1, ctypes.byref(desc_set), 0, None)
        groups_x = (len(inputs_i64) + max(1, local_size_x) - 1) // max(1, local_size_x)
        vk.vkCmdDispatch(cmd_buf, groups_x, 1, 1)
        vk.vkEndCommandBuffer(cmd_buf)

        sub_info = VkSubmitInfo(
            sType=VK_STRUCTURE_TYPE_SUBMIT_INFO,
            commandBufferCount=1,
            pCommandBuffers=ctypes.pointer(cmd_buf),
        )
        if vk.vkQueueSubmit(queue, 1, ctypes.byref(sub_info), 0) != VK_SUCCESS:
            raise RuntimeError("vkQueueSubmit failed")
        vk.vkQueueWaitIdle(queue)

        # Read back results
        out_mapped = ctypes.c_void_p()
        if vk.vkMapMemory(device, out_mem, 0, byte_size, 0, ctypes.byref(out_mapped)) != VK_SUCCESS:
            raise RuntimeError("vkMapMemory failed for output buffer")
        out_raw = ctypes.string_at(out_mapped.value, byte_size)
        vk.vkUnmapMemory(device, out_mem)
        outputs = list(struct.unpack(f"<{len(inputs_i64)}q", out_raw))
        return {
            "executed": True,
            "device_name": chosen_name,
            "groups_x": groups_x,
            "outputs": outputs,
        }
    finally:
        if device.value:
            if cmd_pool.value:
                vk.vkDestroyCommandPool(device, cmd_pool, None)
            if desc_pool.value:
                vk.vkDestroyDescriptorPool(device, desc_pool, None)
            if pipeline.value:
                vk.vkDestroyPipeline(device, pipeline, None)
            if pipe_layout.value:
                vk.vkDestroyPipelineLayout(device, pipe_layout, None)
            if set_layout.value:
                vk.vkDestroyDescriptorSetLayout(device, set_layout, None)
            if shader_mod.value:
                vk.vkDestroyShaderModule(device, shader_mod, None)
            if in_buf.value:
                vk.vkDestroyBuffer(device, in_buf, None)
            if in_mem.value:
                vk.vkFreeMemory(device, in_mem, None)
            if out_buf.value:
                vk.vkDestroyBuffer(device, out_buf, None)
            if out_mem.value:
                vk.vkFreeMemory(device, out_mem, None)
            vk.vkDestroyDevice(device, None)
        if instance.value:
            vk.vkDestroyInstance(instance, None)
