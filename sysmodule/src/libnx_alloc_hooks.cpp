#include <cstddef>
#include <cstdint>
#include <cstdlib>

namespace {

constexpr std::uint64_t LibnxAllocMagic = 0x584E47414C4C4F43ull; // "XNGALLOC"

struct AllocationHeader {
    void* base;
    std::uint64_t magic;
};

void* AllocateWithAlignment(size_t alignment, size_t size) {
    if (alignment < alignof(void*)) {
        alignment = alignof(void*);
    }

    const size_t header_size = sizeof(AllocationHeader);
    const size_t total_size = size + alignment + header_size;
    auto* base = static_cast<std::uint8_t*>(std::malloc(total_size));
    if (base == nullptr) {
        return nullptr;
    }

    uintptr_t aligned = reinterpret_cast<uintptr_t>(base + header_size);
    aligned = (aligned + (alignment - 1)) & ~(static_cast<uintptr_t>(alignment - 1));

    auto* header = reinterpret_cast<AllocationHeader*>(aligned - header_size);
    header->base = base;
    header->magic = LibnxAllocMagic;
    return reinterpret_cast<void*>(aligned);
}

AllocationHeader* GetHeader(void* ptr) {
    if (ptr == nullptr) {
        return nullptr;
    }

    auto* header = reinterpret_cast<AllocationHeader*>(reinterpret_cast<std::uint8_t*>(ptr) - sizeof(AllocationHeader));
    if (header->magic != LibnxAllocMagic) {
        return nullptr;
    }

    return header;
}

} // namespace

extern "C" void* __libnx_alloc(size_t size) {
    return AllocateWithAlignment(alignof(std::max_align_t), size);
}

extern "C" void* __libnx_aligned_alloc(size_t alignment, size_t size) {
    return AllocateWithAlignment(alignment, size);
}

extern "C" void __libnx_free(void* ptr) {
    if (auto* header = GetHeader(ptr); header != nullptr) {
        std::free(header->base);
    }
}
