#pragma once
#include "Common.h"
#include <algorithm>
#include <cstdint>
#include <vector>

static bool Read(uintptr_t address, void *out, size_t size) {
    SIZE_T read{};
    return address && ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void *>(address), out, size, &read) &&
           read == size;
}
template <class T> static T Get(uintptr_t address) {
    T value{};
    Read(address, &value, sizeof(value));
    return value;
}

struct Region {
    uintptr_t address;
    size_t size;
    bool executable;
    bool writable;
};
static std::string Name(uintptr_t pool, uint32_t id) {
    if ((id >> 16) > 8191)
        return {};
    auto block = Get<uintptr_t>(pool + 0x10 + (id >> 16) * 8);
    auto entry = block + (id & 0xffff) * 2;
    auto header = Get<uint16_t>(entry);
    auto length = header >> 6;
    if ((header & 1) || !length || length > 256)
        return {};
    std::string text(length, '\0');
    if (!Read(entry + 2, text.data(), length))
        return {};
    if (std::any_of(text.begin(), text.end(), [](unsigned char c) { return c < 32 || c > 126; }))
        return {};
    return text;
}
struct Objects {
    uintptr_t address;
    uintptr_t chunks;
    int count;
    int stride;
    bool chunked;
    int objectOffset;
    int countOffset;
};
static uintptr_t ObjectAt(const Objects &objects, int index) {
    auto chunk = objects.chunked ? Get<uintptr_t>(objects.chunks + (index / 65536) * 8) : objects.chunks;
    return Get<uintptr_t>(chunk + (objects.chunked ? index % 65536 : index) * objects.stride + objects.objectOffset);
}
