// BattlEye kick crash fix for the Conan Exiles dedicated server, Steam build 26552396 (Akhamet, 13 Nov 2026).
//
// One self-contained winmm.dll. Windows loads it from the server's Win64 folder in place of the system
// winmm.dll; every winmm call the server makes is forwarded to the real System32 winmm.dll unchanged.
//
// The bug: when BattlEye kicks a player, the game's kick callback finds the world through a cached
// game-instance pointer. A dedicated server never sets that pointer, so every BattlEye kick crashed the
// whole server (access violation reading 0x30 in UGameInstance::GetWorld).
//
// The fix:
//  1. Guard. The callback is hooked. While it runs, the null pointer is pointed at the server's live game
//     instance, so the game kicks the player the way it was designed to, and the pointer is set back to null
//     afterwards. If the game instance can't be validated, the kick is skipped (the player stays connected)
//     instead of the server crashing.
//  2. Notice. The kicked player only sees "Connection lost", so a BattlEye kick first shows them a message box
//     with the reason and how to fix it, and the kick itself follows 3 seconds later.
//  3. Monitor. Every BattlEye kick is classified against the player's own BattlEye traffic, and
//     BattlEyeFix.status.json / BattlEyeFix.events.jsonl show when BattlEye's servers are rejecting valid players.
//  4. Re-check (only with BattlEyeFix.recheck). A suspected false kick is held, and the player is registered with
//     BattlEye again for a fresh check, until one passes or the time limit runs out.
//
// Nothing else in the game is changed. Every address is found at startup from the game's own code and
// checked; if anything doesn't match exactly (for example after a game update), the patch logs why and
// leaves the server untouched. Log: BattlEyeFix.log beside the DLL.
//
// Hooking uses MinHook 1.3.4 (third_party/minhook, BSD 2-clause).
#include "Engine.h"
#include "../third_party/minhook/include/MinHook.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <fstream>
#include <bcrypt.h>
#include <deque>
#include <iomanip>
#include <map>
#include <mmsystem.h>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tlhelp32.h>
#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#endif

namespace {
constexpr const char *approvedExecutable = "fe11b4c2292f468b7d3d017261ee7cf5b850537f690bebc6854a4260a05e4394";
constexpr uint64_t kickDelayMs = 3000;

HMODULE self;
std::filesystem::path directory;
void Write(const std::string &message) {
    Log(directory, "BattlEyeFix.log", message);
}
bool FileExists(const wchar_t *name) {
    return GetFileAttributesW((directory / name).c_str()) != INVALID_FILE_ATTRIBUTES;
}
[[noreturn]] void Fail(const std::string &message) {
    throw std::runtime_error(message);
}
std::string Hex(uintptr_t address) {
    std::ostringstream s;
    s << "0x" << std::hex << address;
    return s.str();
}

// ---------------------------------------------------------------------------------------------------------
// Engine discovery: the object registry, the name pool and ProcessEvent, each found by structure.
struct Engine {
    uintptr_t names{};
    Objects objects{};
    uintptr_t processEvent{};
    uintptr_t imageBase{};
    std::vector<Region> sections;
} engine;

std::string HashExecutable() {
    wchar_t path[32768]{};
    GetModuleFileNameW(nullptr, path, ARRAYSIZE(path));
    auto file =
        CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return {};
    BCRYPT_ALG_HANDLE algorithm{};
    BCRYPT_HASH_HANDLE hash{};
    std::string result;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0) {
        if (BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) >= 0) {
            std::vector<unsigned char> buffer(1024 * 1024);
            DWORD count{};
            bool ok = true;
            for (;;) {
                if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &count, nullptr)) {
                    ok = false;
                    break;
                }
                if (!count)
                    break;
                if (BCryptHashData(hash, buffer.data(), count, 0) < 0) {
                    ok = false;
                    break;
                }
            }
            unsigned char digest[32]{};
            if (ok && BCryptFinishHash(hash, digest, sizeof(digest), 0) >= 0) {
                std::ostringstream s;
                for (auto byte : digest)
                    s << std::hex << std::setw(2) << std::setfill('0') << unsigned(byte);
                result = s.str();
            }
            BCryptDestroyHash(hash);
        }
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    CloseHandle(file);
    return result;
}
std::vector<Region> Sections(uintptr_t base) {
    std::vector<Region> result;
    auto dos = Get<IMAGE_DOS_HEADER>(base);
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 || dos.e_lfanew > 4096)
        return result;
    auto nt = Get<IMAGE_NT_HEADERS64>(base + dos.e_lfanew);
    if (nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.FileHeader.NumberOfSections > 32)
        return result;
    auto start =
        base + dos.e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;
    for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
        auto section = Get<IMAGE_SECTION_HEADER>(start + i * sizeof(IMAGE_SECTION_HEADER));
        if (section.VirtualAddress >= nt.OptionalHeader.SizeOfImage ||
            section.Misc.VirtualSize > nt.OptionalHeader.SizeOfImage - section.VirtualAddress)
            continue;
        result.push_back({base + section.VirtualAddress, section.Misc.VirtualSize,
                          bool(section.Characteristics & IMAGE_SCN_MEM_EXECUTE),
                          bool(section.Characteristics & IMAGE_SCN_MEM_WRITE)});
    }
    return result;
}
bool Contains(const std::vector<unsigned char> &code, std::initializer_list<unsigned char> pattern) {
    return std::search(code.begin(), code.end(), pattern.begin(), pattern.end()) != code.end();
}
// ProcessEvent: found through real object vtables, selected by several code signatures and a
// rip-relative reference to the object registry. No fixed address or slot.
uintptr_t ValidateProcessEvent(const Objects &objects, const std::vector<Region> &sections, uintptr_t base) {
    std::set<uintptr_t> tables;
    for (int i = 0; i < std::min(objects.count, 4096); ++i) {
        auto object = ObjectAt(objects, i);
        if (object && Get<int>(object + 0xc) == i)
            tables.insert(Get<uintptr_t>(object));
    }
    std::map<std::pair<uintptr_t, int>, int> candidates;
    std::map<uintptr_t, bool> checked;
    for (auto table : tables)
        for (int slot = 0; slot < 128; ++slot) {
            auto function = Get<uintptr_t>(table + slot * 8);
            if (std::none_of(sections.begin(), sections.end(), [function](auto s) {
                    return s.executable && function >= s.address && function - s.address < s.size;
                }))
                continue;
            if (!checked.count(function)) {
                checked[function] = false;
                DWORD64 imageBase{};
                auto unwind = RtlLookupFunctionEntry(function, &imageBase, nullptr);
                if (!unwind || imageBase != base || imageBase + unwind->BeginAddress != function)
                    continue;
                auto size = unwind->EndAddress - unwind->BeginAddress;
                if (size < 256 || size > 8192)
                    continue;
                std::vector<unsigned char> code(size);
                if (!Read(function, code.data(), size))
                    continue;
                // UFunction native, static and out-parameter flags, plus the return-value frame offset.
                if (!Contains(code, {0xf7, 0x87, 0xb0, 0, 0, 0, 0, 4, 0, 0}) ||
                    !Contains(code, {0xf7, 0x87, 0xb0, 0, 0, 0, 0, 0x80, 0, 0}) ||
                    !Contains(code, {0xf7, 0x87, 0xb0, 0, 0, 0, 0, 0, 0x40, 0}) ||
                    !Contains(code, {0x0f, 0xb7, 0x87, 0xb8, 0, 0, 0}))
                    continue;
                bool registryReference = false;
                for (size_t offset = 0; offset + 7 <= code.size(); ++offset) {
                    if (code[offset] != 0x48 || code[offset + 1] != 0x8b || code[offset + 2] != 0x05)
                        continue;
                    int32_t displacement{};
                    memcpy(&displacement, code.data() + offset + 3, 4);
                    if (function + offset + 7 + displacement == objects.address)
                        registryReference = true;
                }
                checked[function] = registryReference;
            }
            if (checked[function])
                ++candidates[{function, slot}];
        }
    int accepted = 0;
    uintptr_t selected = 0;
    for (auto &entry : candidates)
        if (entry.second >= 3) {
            ++accepted;
            selected = entry.first.first;
        }
    return accepted == 1 ? selected : 0;
}
void DiscoverEngine() {
    auto base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    auto sections = Sections(base);
    std::set<uintptr_t> pools;
    std::vector<Objects> arrays;
    for (auto section : sections) {
        if (!section.writable || section.size > 32 * 1024 * 1024)
            continue;
        std::vector<unsigned char> bytes(section.size);
        if (!Read(section.address, bytes.data(), bytes.size()))
            continue;
        for (size_t offset = 0x10; offset + 32 < bytes.size(); offset += 8) {
            uintptr_t pointer{};
            memcpy(&pointer, bytes.data() + offset, 8);
            if (pointer < 0x10000 || (pointer & 7))
                continue;
            auto candidate = section.address + offset - 0x10;
            auto block = Get<uint32_t>(candidate + 8);
            auto cursor = Get<uint32_t>(candidate + 12);
            if (block < 8192 && cursor <= 0x20000 && Name(candidate, 0) == "None" &&
                Name(candidate, 3) == "ByteProperty")
                pools.insert(candidate);
            for (int header : {8, 16})
                for (bool countFirst : {false, true}) {
                    int capacity{}, count{};
                    memcpy(&capacity, bytes.data() + offset + header, 4);
                    memcpy(&count, bytes.data() + offset + header + 4, 4);
                    if (countFirst)
                        std::swap(capacity, count);
                    if (count < 1000 || count > 4000000 || capacity < count || capacity > 16000000)
                        continue;
                    for (bool chunked : {true, false})
                        for (int stride : {24, 32})
                            for (int objectOffset : {0, 8}) {
                                Objects objects{section.address + offset, pointer, count, stride, chunked, objectOffset,
                                                header + (countFirst ? 0 : 4)};
                                int valid = 0;
                                for (int i = 0; i < std::min(count, 128); ++i) {
                                    auto object = ObjectAt(objects, i);
                                    if (object && Get<int>(object + 0xc) == i && Get<uintptr_t>(object + 0x10))
                                        ++valid;
                                }
                                if (valid >= 32)
                                    arrays.push_back(objects);
                            }
                }
        }
    }
    int anchorSets = 0;
    for (auto pool : pools)
        for (auto objects : arrays) {
            int valid = 0;
            for (int i = 0; i < std::min(objects.count, 1024); ++i) {
                auto object = ObjectAt(objects, i);
                if (!object || Get<int>(object + 0xc) != i)
                    continue;
                auto klass = Get<uintptr_t>(object + 0x10);
                auto classIndex = Get<int>(klass + 0xc);
                if (classIndex < 0 || classIndex >= objects.count || ObjectAt(objects, classIndex) != klass)
                    continue;
                if (Name(pool, Get<uint32_t>(object + 0x18)).empty() || Name(pool, Get<uint32_t>(klass + 0x18)).empty())
                    continue;
                auto function = Get<uintptr_t>(Get<uintptr_t>(object));
                if (std::none_of(sections.begin(), sections.end(), [function](auto s) {
                        return s.executable && function >= s.address && function - s.address < s.size;
                    }))
                    continue;
                ++valid;
            }
            if (valid < 64)
                continue;
            if (auto processEvent = ValidateProcessEvent(objects, sections, base)) {
                ++anchorSets;
                engine = {pool, objects, processEvent, base, sections};
            }
        }
    if (anchorSets != 1)
        Fail("engine_not_uniquely_identified:" + std::to_string(anchorSets));
    Write("Engine found: names " + Hex(engine.names - base) + ", objects " + Hex(engine.objects.address - base) +
          ", ProcessEvent " + Hex(engine.processEvent - base));
}

// ---------------------------------------------------------------------------------------------------------
// Objects. A Handle is a registry slot plus serial number, so a stale object is never used.
struct Handle {
    int index{};
    int serial{};
};
Objects CurrentObjects() {
    auto objects = engine.objects;
    objects.chunks = Get<uintptr_t>(objects.address);
    objects.count = Get<int>(objects.address + objects.countOffset);
    if (!objects.chunks || objects.count < 1000 || objects.count > 4000000)
        Fail("registry_unavailable");
    return objects;
}
uintptr_t ItemAddress(const Objects &objects, int index) {
    if (index < 0 || index >= objects.count)
        return 0;
    auto chunk = objects.chunked ? Get<uintptr_t>(objects.chunks + (index / 65536) * 8) : objects.chunks;
    return chunk + (objects.chunked ? index % 65536 : index) * objects.stride;
}
uintptr_t Resolve(Handle handle, bool allowUnassigned = false) {
    if (handle.serial <= 0 && !allowUnassigned)
        Fail("unassigned_object_serial");
    auto objects = CurrentObjects();
    auto item = ItemAddress(objects, handle.index);
    if (!item || Get<int>(item + 16) != handle.serial)
        Fail("stale_object_handle");
    if (Get<uint32_t>(item + 4) & 0x10200000)
        Fail("object_pending_gc");
    auto object = Get<uintptr_t>(item + objects.objectOffset);
    if (!object || Get<int>(object + 0xc) != handle.index)
        Fail("stale_object_handle");
    return object;
}
Handle Ref(uintptr_t object, bool allowUnassigned = false) {
    if (!object)
        Fail("null_object");
    Handle handle{Get<int>(object + 0xc), 0};
    auto objects = CurrentObjects();
    auto item = ItemAddress(objects, handle.index);
    if (!item || Get<uintptr_t>(item + objects.objectOffset) != object)
        Fail("unregistered_object");
    handle.serial = Get<int>(item + 16);
    if (Resolve(handle, allowUnassigned) != object)
        Fail("object_changed_during_lookup");
    return handle;
}
std::string ObjectName(uintptr_t object) {
    auto name = Name(engine.names, Get<uint32_t>(object + 0x18));
    auto number = Get<uint32_t>(object + 0x1c);
    if (number)
        name += "_" + std::to_string(number - 1);
    return name;
}
bool ClassIs(uintptr_t klass, uintptr_t target) {
    std::set<uintptr_t> seen;
    while (klass && seen.size() < 128 && seen.insert(klass).second) {
        if (klass == target)
            return true;
        klass = Get<uintptr_t>(klass + 0x40);
    }
    return false;
}
struct ClassEntry {
    uintptr_t klass{};
    uintptr_t cdo{};
};
std::map<std::string, ClassEntry> classes; // filled once before any hook, read-only afterwards
uintptr_t Class(const std::string &name) {
    auto found = classes.find(name);
    if (found == classes.end() || !found->second.klass)
        Fail("class_not_found:" + name);
    Ref(found->second.klass, true);
    return found->second.klass;
}
void RequireClass(uintptr_t object, const std::string &name) {
    if (!ClassIs(Get<uintptr_t>(object + 0x10), Class(name)))
        Fail("wrong_object_class:" + name);
}
template <class Visitor> void Snapshot(Visitor visit) {
    auto objects = CurrentObjects();
    for (int first = 0; first < objects.count; first += 65536) {
        auto count = std::min(65536, objects.count - first);
        auto chunk = objects.chunked ? Get<uintptr_t>(objects.chunks + (first / 65536) * 8)
                                     : objects.chunks + first * objects.stride;
        std::vector<unsigned char> items(static_cast<size_t>(count) * objects.stride);
        if (!Read(chunk, items.data(), items.size()))
            continue;
        for (int local = 0; local < count; ++local) {
            auto item = items.data() + local * objects.stride;
            uintptr_t object{};
            uint32_t flags{};
            int serial{};
            memcpy(&object, item + objects.objectOffset, 8);
            memcpy(&flags, item + 4, 4);
            memcpy(&serial, item + 16, 4);
            if (!object || (flags & 0x10200000))
                continue;
            std::array<unsigned char, 48> header{};
            if (!Read(object, header.data(), header.size()))
                continue;
            int index{};
            uintptr_t klass{};
            uint32_t objectFlags{};
            memcpy(&index, header.data() + 0xc, 4);
            memcpy(&klass, header.data() + 0x10, 8);
            memcpy(&objectFlags, header.data() + 8, 4);
            if (index != first + local || !klass)
                continue;
            visit(object, klass, objectFlags, Handle{index, serial});
        }
    }
}
void IndexClasses() {
    auto objects = CurrentObjects();
    uintptr_t metaClass{};
    for (int i = 0; i < std::min(objects.count, 4096); ++i) {
        auto klass = Get<uintptr_t>(ObjectAt(objects, i) + 0x10);
        if (Name(engine.names, Get<uint32_t>(klass + 0x18)) == "Class") {
            metaClass = klass;
            break;
        }
    }
    if (!metaClass)
        Fail("native_metaclass_not_found");
    std::map<uintptr_t, bool> isClass;
    Snapshot([&](uintptr_t object, uintptr_t klass, uint32_t, Handle) {
        auto found = isClass.find(klass);
        bool match = found != isClass.end() ? found->second : (isClass[klass] = ClassIs(klass, metaClass));
        if (!match)
            return;
        auto package = ObjectName(Get<uintptr_t>(object + 0x20));
        if (package != "/Script/ConanSandbox" && package != "/Script/Engine" && package != "/Script/CoreUObject")
            return;
        auto name = ObjectName(object);
        if (classes.count(name))
            Fail("ambiguous_native_class:" + name);
        classes[name].klass = object;
    });
    std::map<uintptr_t, std::string> classNames;
    for (auto &pair : classes)
        classNames[pair.second.klass] = pair.first;
    Snapshot([&](uintptr_t object, uintptr_t klass, uint32_t flags, Handle) {
        if ((flags & 0x10) && classNames.count(klass))
            classes[classNames.at(klass)].cdo = object;
    });
}
uintptr_t Default(const std::string &name) {
    Class(name);
    auto pointer = classes.at(name).cdo;
    if (!pointer)
        Fail("default_object_not_found:" + name);
    Ref(pointer, true);
    return pointer;
}
std::vector<Handle> FindLive(const std::string &className, size_t limit) {
    auto desired = Class(className);
    std::vector<Handle> found;
    std::map<uintptr_t, bool> matches;
    Snapshot([&](uintptr_t, uintptr_t klass, uint32_t flags, Handle h) {
        if (flags & (0x10 | 0x20) || h.serial <= 0)
            return;
        auto known = matches.find(klass);
        bool match = known != matches.end() ? known->second : (matches[klass] = ClassIs(klass, desired));
        if (match && found.size() < limit)
            found.push_back(h);
    });
    return found;
}

// ---------------------------------------------------------------------------------------------------------
// Reflection: just enough to call two game functions with checked parameter layouts.
struct Property {
    std::string name, type;
    uintptr_t address{};
    int offset{}, size{}, arrayDim{};
    uint64_t flags{};
};
Property FieldAt(uintptr_t field) {
    auto type = Get<uintptr_t>(field + 8);
    Property p{Name(engine.names, Get<uint32_t>(field + 0x20)), Name(engine.names, Get<uint32_t>(type + 8)), field,
               Get<int>(field + 0x44), Get<int>(field + 0x34), Get<int>(field + 0x30), Get<uint64_t>(field + 0x38)};
    if (p.name.empty() || p.type.empty() || p.offset < 0 || p.offset > 0x100000 || p.size <= 0 ||
        p.size > 0x100000 || p.arrayDim <= 0)
        Fail("invalid_reflection_field");
    return p;
}
std::vector<Property> Fields(uintptr_t structure) {
    std::vector<Property> fields;
    std::set<uintptr_t> seen;
    auto field = Get<uintptr_t>(structure + 0x50);
    while (field && seen.size() < 512 && seen.insert(field).second) {
        fields.push_back(FieldAt(field));
        field = Get<uintptr_t>(field + 0x18);
    }
    if (field)
        Fail("invalid_reflection_chain");
    return fields;
}
struct Function {
    uintptr_t address{};
    uint32_t flags{};
    int size{};
    std::vector<Property> parameters;
};
Function FindFunction(uintptr_t klass, const std::string &name) {
    std::set<uintptr_t> classesSeen;
    for (; klass && classesSeen.size() < 128 && classesSeen.insert(klass).second;
         klass = Get<uintptr_t>(klass + 0x40)) {
        auto field = Get<uintptr_t>(klass + 0x48);
        std::set<uintptr_t> seen;
        while (field && seen.size() < 8192 && seen.insert(field).second) {
            if (ObjectName(field) == name && Get<uintptr_t>(field + 0x20) == klass &&
                ClassIs(Get<uintptr_t>(field + 0x10), Class("Function"))) {
                Function fn{field, Get<uint32_t>(field + 0xb0), Get<uint16_t>(field + 0xb6), {}};
                if (fn.size > 512)
                    Fail("parameter_frame_too_large");
                for (auto &p : Fields(field))
                    if (p.flags & 0x80) {
                        if (p.arrayDim != 1 || p.offset + p.size > fn.size)
                            Fail("invalid_parameter_bounds");
                        fn.parameters.push_back(p);
                    }
                if (fn.parameters.size() != Get<uint8_t>(field + 0xb4))
                    Fail("parameter_count_mismatch");
                return fn;
            }
            field = Get<uintptr_t>(field + 0x28);
        }
    }
    Fail("function_not_found:" + name);
}

// ---------------------------------------------------------------------------------------------------------
// Code checks.
bool InExecutableSection(uintptr_t pointer, bool executable) {
    return std::any_of(engine.sections.begin(), engine.sections.end(), [&](auto s) {
        return s.executable == executable && pointer >= s.address && pointer - s.address < s.size;
    });
}
bool InWritableData(uintptr_t pointer) {
    return std::any_of(engine.sections.begin(), engine.sections.end(), [&](auto s) {
        return !s.executable && s.writable && pointer >= s.address && pointer - s.address < s.size;
    });
}
// Pattern bytes; -1 matches anything and -2 captures one byte into captured.
bool CodeMatches(uintptr_t code, std::initializer_list<int> pattern, int *captured = nullptr) {
    std::vector<unsigned char> bytes(pattern.size());
    if (!Read(code, bytes.data(), bytes.size()))
        return false;
    size_t i = 0;
    for (auto expected : pattern) {
        if (expected == -2 && captured)
            *captured = bytes[i];
        else if (expected >= 0 && bytes[i] != expected)
            return false;
        ++i;
    }
    return true;
}
std::vector<unsigned char> FunctionCode(uintptr_t function) {
    DWORD64 base{};
    auto unwind = RtlLookupFunctionEntry(function, &base, nullptr);
    if (!unwind || base != engine.imageBase || base + unwind->BeginAddress != function ||
        unwind->EndAddress <= unwind->BeginAddress)
        Fail("native_function_boundary_not_validated");
    auto size = unwind->EndAddress - unwind->BeginAddress;
    if (size > 4096)
        Fail("native_function_too_large");
    std::vector<unsigned char> code(size + 16);
    if (!Read(function, code.data(), size))
        Fail("native_code_unreadable");
    return code;
}
std::vector<uintptr_t> FindInSections(const std::vector<unsigned char> &pattern, bool executable) {
    std::vector<uintptr_t> found;
    for (auto section : engine.sections) {
        if (section.executable != executable)
            continue;
        std::vector<unsigned char> bytes(section.size);
        if (!Read(section.address, bytes.data(), bytes.size()))
            continue;
        for (auto at = bytes.begin();;) {
            at = std::search(at, bytes.end(), pattern.begin(), pattern.end());
            if (at == bytes.end())
                break;
            found.push_back(section.address + static_cast<uintptr_t>(at - bytes.begin()));
            ++at;
        }
    }
    return found;
}
// rip-relative `lea rcx, [target]` instructions in code.
std::vector<uintptr_t> LeaRcxTo(uintptr_t target) {
    std::vector<uintptr_t> found;
    for (auto section : engine.sections) {
        if (!section.executable)
            continue;
        std::vector<unsigned char> code(section.size);
        if (!Read(section.address, code.data(), code.size()))
            continue;
        for (size_t i = 0; i + 7 <= code.size(); ++i) {
            if (code[i] != 0x48 || code[i + 1] != 0x8d || code[i + 2] != 0x0d)
                continue;
            int32_t displacement{};
            memcpy(&displacement, &code[i + 3], 4);
            if (section.address + i + 7 + displacement == target)
                found.push_back(section.address + i);
        }
    }
    return found;
}

// ---------------------------------------------------------------------------------------------------------
// Game thread: the process's main thread, confirmed against the engine's own game-thread id global.
uintptr_t gameThreadIdAddress{};
DWORD gameThreadId{};
DWORD OldestThread() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        Fail("thread_snapshot_failed");
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    DWORD selected{};
    uint64_t earliest = UINT64_MAX;
    if (Thread32First(snapshot, &entry))
        do {
            if (entry.th32OwnerProcessID != GetCurrentProcessId())
                continue;
            HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ThreadID);
            if (!thread)
                continue;
            FILETIME created{}, exited{}, kernel{}, user{};
            if (GetThreadTimes(thread, &created, &exited, &kernel, &user)) {
                uint64_t time = (static_cast<uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
                if (time < earliest) {
                    earliest = time;
                    selected = entry.th32ThreadID;
                }
            }
            CloseHandle(thread);
        } while (Thread32Next(snapshot, &entry));
    CloseHandle(snapshot);
    if (!selected)
        Fail("main_thread_not_identified");
    return selected;
}
void DiscoverGameThread() {
    auto main = OldestThread();
    auto imported =
        reinterpret_cast<uintptr_t>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetCurrentThreadId"));
    std::set<uintptr_t> matches;
    for (auto section : engine.sections) {
        if (!section.executable)
            continue;
        std::vector<unsigned char> code(section.size);
        if (!Read(section.address, code.data(), code.size()))
            continue;
        for (size_t i = 0; i + 12 <= code.size(); ++i) {
            if (code[i] != 0xff || code[i + 1] != 0x15 || code[i + 6] != 0x3b || code[i + 7] != 0x05)
                continue;
            int32_t displacement{}, compare{};
            memcpy(&displacement, code.data() + i + 2, 4);
            memcpy(&compare, code.data() + i + 8, 4);
            if (Get<uintptr_t>(section.address + i + 6 + displacement) != imported)
                continue;
            auto global = section.address + i + 12 + compare;
            if (Get<DWORD>(global) != main)
                continue;
            int initializers = 0;
            for (size_t j = 0; j + 13 <= code.size(); ++j) {
                if (code[j] != 0xc6 || code[j + 1] != 0x05 || code[j + 6] != 1 || code[j + 7] != 0x89 ||
                    code[j + 8] != 0x05)
                    continue;
                int32_t write{};
                memcpy(&write, code.data() + j + 9, 4);
                if (section.address + j + 13 + write == global)
                    ++initializers;
            }
            if (initializers >= 2)
                matches.insert(global);
        }
    }
    if (matches.size() != 1)
        Fail("game_thread_global_not_uniquely_validated");
    gameThreadIdAddress = *matches.begin();
    gameThreadId = main;
}
bool OnGameThread() {
    return GetCurrentThreadId() == gameThreadId &&
           *reinterpret_cast<const volatile DWORD *>(gameThreadIdAddress) == gameThreadId;
}

// ---------------------------------------------------------------------------------------------------------
// Game-owned text (FText) for the message box. The game builds it with KismetTextLibrary.Conv_StringToText,
// so the engine allocates and frees it. AddRef, Release and GetSourceString are identified by their exact
// instruction bytes, and an AddRef/Release round trip must move the counter 1 -> 2 -> 1. Any mismatch turns
// the notice off; the guard keeps working.
using ProcessEventFn = void (*)(void *, void *, void *);
ProcessEventFn originalEvent{};
struct TextFactory {
    bool checked{}, valid{};
    std::string failure;
    uintptr_t library{}, function{}, vtable{}, release{};
    int refOffset{-1};
} textFactory;
using AddRefMethod = void (*)(uintptr_t);
using ReleaseMethod = void *(*)(uintptr_t, uint32_t *);
uintptr_t TextMethodAt(uintptr_t vtable, int slot) {
    auto method = Get<uintptr_t>(vtable + 8 * slot);
    if (!InExecutableSection(method, true))
        Fail("text_method_outside_code");
    return method;
}
std::vector<wchar_t> WideText(const std::string &value) {
    auto size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
                                    nullptr, 0);
    if (!value.empty() && size <= 0)
        Fail("invalid_utf8_text");
    std::vector<wchar_t> result(static_cast<size_t>(size) + 1, L'\0');
    if (size)
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(),
                            size);
    return result;
}
std::array<unsigned char, 16> BuildText(const std::string &text) {
    auto wide = WideText(text);
    alignas(16) std::array<unsigned char, 32> frame{};
    auto data = reinterpret_cast<uintptr_t>(wide.data());
    int count = static_cast<int>(wide.size());
    memcpy(frame.data(), &data, 8);
    memcpy(frame.data() + 8, &count, 4);
    memcpy(frame.data() + 12, &count, 4);
    originalEvent(reinterpret_cast<void *>(textFactory.library), reinterpret_cast<void *>(textFactory.function),
                  frame.data());
    std::array<unsigned char, 16> result{};
    memcpy(result.data(), frame.data() + 16, 16);
    if (!*reinterpret_cast<uintptr_t *>(result.data()))
        Fail("text_factory_returned_empty");
    return result;
}
std::wstring ReadFStringAt(uintptr_t address) {
    auto chars = Get<uintptr_t>(address);
    auto count = Get<int>(address + 8);
    if (count < 1 || count > 8192 || !chars)
        Fail("text_source_unreadable");
    std::wstring value(static_cast<size_t>(count - 1), L'\0');
    if (count > 1 && !Read(chars, value.data(), (count - 1) * sizeof(wchar_t)))
        Fail("text_source_unreadable");
    return value;
}
void ReleaseText(uintptr_t data) {
    uint32_t remaining{};
    reinterpret_cast<ReleaseMethod>(textFactory.release)(data, &remaining);
}
void ValidateTextFactory() {
    textFactory.checked = true;
    try {
        auto fn = FindFunction(Class("KismetTextLibrary"), "Conv_StringToText");
        if (!(fn.flags & 0x2000) || fn.size != 32 || fn.parameters.size() != 2 ||
            fn.parameters[0].type != "StrProperty" || fn.parameters[0].offset != 0 ||
            fn.parameters[1].type != "TextProperty" || fn.parameters[1].offset != 16 ||
            !(fn.parameters[1].flags & 0x400))
            Fail("text_factory_schema_mismatch");
        textFactory.library = Default("KismetTextLibrary");
        textFactory.function = fn.address;
        auto bytes = BuildText("BattlEyeFix text probe");
        auto data = *reinterpret_cast<uintptr_t *>(bytes.data());
        auto vtable = Get<uintptr_t>(data);
        if (!InExecutableSection(vtable, false))
            Fail("text_vtable_outside_image");
        int refOffset = -1, releaseOffset = -1, sourceOffset = -1;
        auto addRef = TextMethodAt(vtable, 1), release = TextMethodAt(vtable, 2), source = TextMethodAt(vtable, 4);
        // AddRef: lock inc dword [rcx+N]; ret
        if (!CodeMatches(addRef, {0xF0, 0xFF, 0x41, -2, 0xC3}, &refOffset))
            Fail("text_addref_not_identified");
        // Release(this, result*): mov [rsp+8], rbx; push rdi; sub rsp, 20h; mov rdi, rdx; lea rax, [rcx+N]
        if (!CodeMatches(release, {0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xFA, 0x48,
                                   0x8D, 0x41, -2},
                         &releaseOffset) ||
            releaseOffset != refOffset)
            Fail("text_release_not_identified");
        // GetSourceString: lea rax, [rcx+N]; ret
        if (!CodeMatches(source, {0x48, 0x8D, 0x41, -2, 0xC3}, &sourceOffset))
            Fail("text_source_accessor_not_identified");
        if (ReadFStringAt(data + sourceOffset) != L"BattlEyeFix text probe")
            Fail("text_source_mismatch");
        if (Get<int>(data + refOffset) != 1)
            Fail("text_refcount_not_one");
        textFactory.release = release;
        reinterpret_cast<AddRefMethod>(addRef)(data);
        auto raised = Get<int>(data + refOffset);
        ReleaseText(data);
        if (raised != 2 || Get<int>(data + refOffset) != 1)
            Fail("text_refcount_round_trip_failed");
        ReleaseText(data); // our single reference: frees the probe through the engine's own path
        textFactory.vtable = vtable;
        textFactory.refOffset = refOffset;
        textFactory.valid = true;
    } catch (const std::exception &e) {
        textFactory.failure = e.what();
        Write(std::string("Kick message disabled: text factory not validated: ") + e.what());
    }
}
class OwnedText {
  public:
    explicit OwnedText(const std::string &text) {
        if (!OnGameThread())
            Fail("not_validated_game_thread");
        if (!textFactory.checked)
            ValidateTextFactory();
        if (!textFactory.valid)
            Fail("text_factory_unavailable:" + textFactory.failure);
        bytes = BuildText(text);
        if (Get<uintptr_t>(Data()) != textFactory.vtable) {
            bytes = {};
            Fail("text_data_type_changed");
        }
    }
    ~OwnedText() {
        auto data = Data();
        if (data && Get<int>(data + textFactory.refOffset) == 1)
            ReleaseText(data);
    }
    OwnedText(const OwnedText &) = delete;
    OwnedText &operator=(const OwnedText &) = delete;
    std::array<unsigned char, 16> bytes{};
    uintptr_t Data() const { return *reinterpret_cast<const uintptr_t *>(bytes.data()); }
};
// The game's own rich message box, on one client.
void SendMessageBox(uintptr_t controller, const std::string &title, const std::string &message) {
    Ref(controller, true);
    RequireClass(controller, "ConanPlayerController");
    auto fn = FindFunction(Get<uintptr_t>(controller + 0x10), "ClientShowRichMessageBox");
    if ((fn.flags & (0x40u | 0x1000000u)) != (0x40u | 0x1000000u) || fn.size != 32 || fn.parameters.size() != 2 ||
        fn.parameters[0].type != "TextProperty" || fn.parameters[0].offset != 0 ||
        fn.parameters[1].type != "TextProperty" || fn.parameters[1].offset != 16)
        Fail("client_message_box_schema_mismatch");
    OwnedText heading(title), body(message);
    alignas(16) std::array<unsigned char, 32> frame{};
    memcpy(frame.data(), heading.bytes.data(), 16);
    memcpy(frame.data() + 16, body.bytes.data(), 16);
    originalEvent(reinterpret_cast<void *>(controller), reinterpret_cast<void *>(fn.address), frame.data());
}

// ---------------------------------------------------------------------------------------------------------
// The guard.
using BattlEyeKick = void (*)(int, const char *);
using GameInstanceWorld = uintptr_t (*)(uintptr_t);
BattlEyeKick originalBattlEyeKick{};
GameInstanceWorld gameInstanceWorld{};
uintptr_t battlEyeKickCode{}, battlEyeInstanceSlot{};
int32_t worldGameModeOffset{}, gameModeSessionOffset{};
std::mutex instanceMutex; // the game thread only try-locks it
std::optional<Handle> liveInstance;

using KickPlayerFn = bool (*)(void *, void *, const void *);
KickPlayerFn originalKickPlayer{};
int32_t sessionKickSlot{};
uint32_t receiveTickName{};
bool inBattlEyeKick = false; // game thread only
std::string kickReason;      // game thread only
struct HeldKick {
    Handle session, controller;
    std::string reason;
    uint64_t at;
};
std::deque<HeldKick> heldKicks; // game thread only
std::atomic<bool> noticeOff{false};

// The callback is found from its own log line, then every piece it relies on is checked against the code.
void FindBattlEyeKick() {
    const std::wstring text = L"BattlEyeServer: BattlEye kicked the player %d because: %s";
    std::vector<unsigned char> pattern(reinterpret_cast<const unsigned char *>(text.c_str()),
                                       reinterpret_cast<const unsigned char *>(text.c_str()) +
                                           (text.size() + 1) * sizeof(wchar_t));
    auto strings = FindInSections(pattern, false);
    if (strings.size() != 1)
        Fail("battleye_kick_text_matches:" + std::to_string(strings.size()));
    // The log call passes a static record whose first field points at the format text.
    std::vector<unsigned char> pointer(8);
    memcpy(pointer.data(), &strings[0], 8);
    std::set<uintptr_t> functions;
    for (auto record : FindInSections(pointer, false))
        for (auto lea : LeaRcxTo(record)) {
            DWORD64 base{};
            if (auto entry = RtlLookupFunctionEntry(lea, &base, nullptr); entry && base == engine.imageBase)
                functions.insert(base + entry->BeginAddress);
        }
    if (functions.size() != 1)
        Fail("battleye_kick_callback_matches:" + std::to_string(functions.size()));
    auto callback = *functions.begin();
    auto code = FunctionCode(callback);
    // mov [rsp+18h], rbx; mov [rsp+20h], rbp; push rsi; push rdi; push r14: (int player, const char *reason)
    static const unsigned char prologue[] = {0x48, 0x89, 0x5c, 0x24, 0x18, 0x48, 0x89, 0x6c,
                                             0x24, 0x20, 0x56, 0x57, 0x41, 0x56};
    if (code.size() < sizeof(prologue) || memcmp(code.data(), prologue, sizeof(prologue)))
        Fail("battleye_kick_prologue_mismatch");
    // mov rcx, [slot]; call GetWorld; mov rcx, [rax + AuthorityGameMode]; mov r14, [rcx + GameSession]
    size_t site = 0, sites = 0;
    for (size_t i = 0; i + 26 <= code.size(); ++i)
        if (code[i] == 0x48 && code[i + 1] == 0x8b && code[i + 2] == 0x0d && code[i + 7] == 0xe8 &&
            code[i + 12] == 0x48 && code[i + 13] == 0x8b && code[i + 14] == 0x88 && code[i + 19] == 0x4c &&
            code[i + 20] == 0x8b && code[i + 21] == 0xb1) {
            site = i;
            ++sites;
        }
    if (sites != 1)
        Fail("battleye_kick_world_lookup_matches:" + std::to_string(sites));
    int32_t slotDisplacement{}, callDisplacement{};
    memcpy(&slotDisplacement, &code[site + 3], 4);
    memcpy(&callDisplacement, &code[site + 8], 4);
    memcpy(&worldGameModeOffset, &code[site + 15], 4);
    memcpy(&gameModeSessionOffset, &code[site + 22], 4);
    auto slot = callback + site + 7 + slotDisplacement;
    auto getter = callback + site + 12 + callDisplacement;
    if (!InWritableData(slot))
        Fail("battleye_kick_slot_not_data");
    // GetWorld: mov rax, [rcx+30h]; test rax, rax; jz; mov rax, [rax+2C0h]; ret. It doesn't check rcx itself.
    if (!CodeMatches(getter, {0x48, 0x8b, 0x41, -1, 0x48, 0x85, 0xc0, 0x74, -1, 0x48, 0x8b, 0x80, -1, -1, -1, -1,
                              0xc3}))
        Fail("battleye_kick_get_world_mismatch");
    if (worldGameModeOffset <= 0 || worldGameModeOffset > 0x2000 || gameModeSessionOffset <= 0 ||
        gameModeSessionOffset > 0x2000)
        Fail("battleye_kick_offsets_out_of_range");
    // Both kick paths call GameSession->KickPlayer(controller, reason) through the same vtable slot.
    std::set<int32_t> kickSlots;
    for (size_t i = 0; i + 10 <= code.size(); ++i)
        if ((code[i] == 0x49 && code[i + 1] == 0x8b && code[i + 2] == 0x0e && code[i + 3] == 0x48 &&
             code[i + 4] == 0x8b && code[i + 5] == 0x99) ||
            (code[i] == 0x48 && code[i + 1] == 0x8b && code[i + 2] == 0x17 && code[i + 3] == 0x48 &&
             code[i + 4] == 0x8b && code[i + 5] == 0x9a)) {
            int32_t kickSlot{};
            memcpy(&kickSlot, &code[i + 6], 4);
            kickSlots.insert(kickSlot);
        }
    if (kickSlots.size() == 1 && *kickSlots.begin() > 0 && *kickSlots.begin() < 0x2000 && *kickSlots.begin() % 8 == 0)
        sessionKickSlot = *kickSlots.begin();
    else
        Write("Kick message disabled: KickPlayer slot not found (" + std::to_string(kickSlots.size()) +
              " candidates)");
    battlEyeInstanceSlot = slot;
    gameInstanceWorld = reinterpret_cast<GameInstanceWorld>(getter);
    battlEyeKickCode = callback;
    Write("BattlEye kick callback found at " + Hex(callback - engine.imageBase) + ", game-instance pointer at " +
          Hex(slot - engine.imageBase) + " (" + (Get<uintptr_t>(slot) ? "set" : "null, so kicks would crash") + ")");
}
// Worker thread: keeps a handle to the live game instance for the hook to revalidate.
void RefreshInstance() {
    {
        std::lock_guard<std::mutex> lock(instanceMutex);
        if (liveInstance)
            try {
                Resolve(*liveInstance);
                return;
            } catch (...) {
            }
    }
    auto found = FindLive("GameInstance", 4);
    std::lock_guard<std::mutex> lock(instanceMutex);
    if (found.size() == 1)
        liveInstance = found[0];
    else
        liveInstance.reset();
}
// The live game instance, only if the world it gives has the game mode and a game session, which is
// everything the callback reads from it.
uintptr_t ValidatedInstance(uintptr_t *gameSessionOut = nullptr) {
    std::optional<Handle> handle;
    {
        std::unique_lock<std::mutex> lock(instanceMutex, std::try_to_lock);
        if (!lock.owns_lock())
            Fail("game_instance_lookup_busy");
        handle = liveInstance;
    }
    if (!handle)
        Fail("game_instance_not_found");
    auto instance = Resolve(*handle);
    RequireClass(instance, "GameInstance");
    auto world = gameInstanceWorld(instance);
    if (!world)
        Fail("game_instance_has_no_world");
    RequireClass(world, "World");
    auto mode = Get<uintptr_t>(world + worldGameModeOffset);
    if (!mode)
        Fail("world_has_no_game_mode");
    RequireClass(mode, "ConanGameMode");
    auto gameSession = Get<uintptr_t>(mode + gameModeSessionOffset);
    if (!gameSession)
        Fail("game_mode_has_no_session");
    RequireClass(gameSession, "GameSession");
    if (gameSessionOut)
        *gameSessionOut = gameSession;
    return instance;
}
bool ClassifyKick(int player, const std::string &reason);
extern int recheckKickPlayer;
bool lastKickHeld = false; // game thread only: the last guarded kick was held instead of carried out
void RunOriginalKick(int player, const char *reason, const std::string &why) {
    bool gameThread = GetCurrentThreadId() == gameThreadId;
    if (gameThread) {
        inBattlEyeKick = true;
        kickReason = why;
        recheckKickPlayer = -1;
        try {
            if (ClassifyKick(player, why))
                recheckKickPlayer = player;
        } catch (const std::exception &e) {
            Write(std::string("BattlEye kick classification failed: ") + e.what());
        }
    }
    originalBattlEyeKick(player, reason);
    if (gameThread) {
        inBattlEyeKick = false;
        recheckKickPlayer = -1;
    }
}
void BattlEyeKickHook(int player, const char *reason) {
    std::string why;
    if (reason)
        why.assign(reason, strnlen(reason, 160));
    auto slot = reinterpret_cast<volatile uintptr_t *>(battlEyeInstanceSlot);
    auto label = "BattlEye kick of player " + std::to_string(player) + " (" + why + "): ";
    if (*slot) {
        Write(label + "pointer already set, game handled it");
        RunOriginalKick(player, reason, why);
        return;
    }
    uintptr_t instance = 0;
    std::string problem;
    try {
        if (GetCurrentThreadId() != gameThreadId)
            Fail("not_game_thread");
        instance = ValidatedInstance();
    } catch (const std::exception &e) {
        problem = e.what();
    }
    if (!instance) {
        Write(label + "skipped to avoid the crash, player not kicked: " + problem);
        return;
    }
    *slot = instance;
    lastKickHeld = false;
    RunOriginalKick(player, reason, why);
    *slot = 0;
    Write(label + (lastKickHeld ? "handled safely, held for a re-check" : "kicked safely"));
}

// ---------------------------------------------------------------------------------------------------------
// The kick message.
std::string KickNotice(const std::string &reason) {
    std::string text;
    if (reason.find("Query Timeout") != std::string::npos || reason.find("not responding") != std::string::npos)
        text = "BattlEye on your PC stopped answering the server (" + reason +
               ").\n\nRestarting the game usually fixes this. If it keeps happening:\n"
               "- Update or reinstall BattlEye: close the game, open the Conan Exiles install folder, go to "
               "ConanSandbox\\Binaries\\Win64\\BattlEye, run Uninstall_BattlEye.bat and then Install_BattlEye.bat\n"
               "- Verify the game files in Steam\n"
               "- Check that your firewall or antivirus isn't blocking BattlEye";
    else
        text = "Reason: " + reason +
               "\n\nIf you think this is a mistake, update or reinstall BattlEye: close the game, open the Conan "
               "Exiles install folder, go to ConanSandbox\\Binaries\\Win64\\BattlEye, run Uninstall_BattlEye.bat and "
               "then Install_BattlEye.bat";
    return text + "\n\nYou will be disconnected in a few seconds.";
}
void HoldForRecheck(void *controller, int player);
// Game thread. Only kicks made by the BattlEye callback are held; every other kick goes straight through.
bool KickPlayerHook(void *session, void *controller, const void *reason) {
    if (inBattlEyeKick && recheckKickPlayer >= 0 && GetCurrentThreadId() == gameThreadId)
        try {
            HoldForRecheck(controller, recheckKickPlayer);
            lastKickHeld = true;
            Write("BattlEye kick held for a re-check (" + kickReason + ")");
            return true;
        } catch (const std::exception &e) {
            Write(std::string("BattlEye re-check hold failed, kicking as normal: ") + e.what());
        }
    if (!inBattlEyeKick || noticeOff || GetCurrentThreadId() != gameThreadId)
        return originalKickPlayer(session, controller, reason);
    try {
        auto held = HeldKick{Ref(reinterpret_cast<uintptr_t>(session)), Ref(reinterpret_cast<uintptr_t>(controller)),
                             kickReason, GetTickCount64()};
        SendMessageBox(reinterpret_cast<uintptr_t>(controller), "Disconnected by BattlEye", KickNotice(kickReason));
        if (heldKicks.size() >= 64)
            Fail("too_many_held_kicks");
        heldKicks.push_back(std::move(held));
        Write("Kick message shown, kick follows in " + std::to_string(kickDelayMs / 1000) + " s");
        return true;
    } catch (const std::exception &e) {
        Write(std::string("Kick message failed, kicking now: ") + e.what());
        return originalKickPlayer(session, controller, reason);
    }
}
// Game thread: kicks whose message has had time to arrive.
void HeldKickTick() {
    auto now = GetTickCount64();
    while (!heldKicks.empty() && now - heldKicks.front().at >= kickDelayMs) {
        auto kick = std::move(heldKicks.front());
        heldKicks.pop_front();
        try {
            auto session = Resolve(kick.session);
            auto controller = Resolve(kick.controller);
            OwnedText reason("BattlEye: " + kick.reason);
            originalKickPlayer(reinterpret_cast<void *>(session), reinterpret_cast<void *>(controller),
                               reason.bytes.data());
            Write("Held kick done (" + kick.reason + ")");
        } catch (const std::exception &e) {
            Write("Held kick dropped, player already gone (" + kick.reason + "): " + e.what());
        }
    }
}
// ---------------------------------------------------------------------------------------------------------
// BattlEye monitor and re-check.
//
// On 14 November 2026 BattlEye's central servers rejected valid players in windows that switched for every
// Conan server at once. The player's BattlEye answered the join check (a ~926-byte reply), the server passed it
// on to BattlEye, and about 0.5 s later BattlEye sent back a kick with the misleading reason "Client not
// responding". A real "not responding" kick has no such reply just before it.
//
// Monitor (always on): every BattlEye kick is classified and logged, and BattlEyeFix.status.json shows whether
// BattlEye looks healthy or degraded. BattlEyeFix.events.jsonl gets one line per event.
// Re-check (off unless BattlEyeFix.recheck exists): a suspected false kick is not carried out. The player is
// taken off BattlEye and registered again after retrySeconds, so BattlEye runs a fresh check, until one passes or
// holdSeconds runs out and the player is kicked as normal. While held, the player isn't protected by BattlEye.
// Lines in BattlEyeFix.recheck (key=value) override the defaults in RecheckSettings.
//
// BattlEye's server interface lives in a table the game fills when BattlEye loads: AddPlayer(id, ip, port,
// name), ChangePlayerStatus(id, status), ReceivedPacket(id, data, size). The game's own register (by
// controller), unregister (by unique net id) and login step (unique net id -> controller) are reused.
using BeReceivedPacket = void (*)(int, const void *, int);
using BeAddPlayer = void (*)(int, unsigned long, unsigned short, const char *);
using BeUnregister = void (*)(const void *);
using BeRegister = void (*)(void *);
using BeAddUniqueId = void (*)(const void *, void *);
uintptr_t beReceivedSlot{}, beAddPlayerSlot{};
BeReceivedPacket originalBeReceived{};
BeAddPlayer originalBeAddPlayer{};
BeUnregister beUnregister{};
BeRegister beRegister{};
BeAddUniqueId beAddUniqueId{};
struct RecheckSettings {
    bool hold = false;
    int minReplyBytes = 500;    // a reply at least this big counts as "the player's BattlEye answered"
    int replyWindowMs = 2000;   // ...if it arrived this soon before the kick
    int firstCheckSeconds = 90; // only kicks this soon after registering (the join check) qualify
    int retrySeconds = 30;      // wait before registering again
    int holdSeconds = 1200;     // give up and kick as normal after this long
    int degradedKicks = 3;      // suspected false kicks within degradedWindowSeconds that mean "degraded"
    int degradedWindowSeconds = 600;
    bool notify = true; // tell held players what is going on
};
std::mutex settingsMutex;
RecheckSettings settings;
RecheckSettings CurrentSettings() {
    std::lock_guard<std::mutex> lock(settingsMutex);
    return settings;
}
struct BeTrace {
    uint64_t registeredAt{}, lastReplyAt{};
    int lastReplyBytes{}, largestReply{};
    uint64_t packets{};
    bool kicked{}, passed{};
};
std::map<int, BeTrace> beTraces; // game thread only
struct Recheck {
    Handle controller;
    uint64_t firstAt{}, unregisteredAt{};
    int pid{-1}, attempts{};
    bool unregistered{}, registered{};
};
std::deque<Recheck> rechecks;  // game thread only
Recheck *beRegistering{};      // game thread only
int recheckKickPlayer = -1;    // game thread only
std::deque<uint64_t> suspectedTimes; // game thread only
std::atomic<bool> beDegraded{false};
std::atomic<uint64_t> suspectedKicks{0}, normalKicks{0}, heldForRecheck{0}, reregistrations{0}, passedAfterRecheck{0},
    gaveUp{0}, droppedRechecks{0}, recheckErrors{0}, joinChecksPassed{0}, lastStepUs{0}, maxStepUs{0};
std::atomic<uint64_t> lastSuspectedUtcMs{0}, lastDegradedUtcMs{0}, lastRecoveredUtcMs{0}, startedUtcMs{0};
std::mutex eventMutex;
std::deque<std::string> recentEvents; // JSON lines
std::string recheckProblem;           // set once at startup

uint64_t UtcMs() {
    FILETIME t{};
    GetSystemTimeAsFileTime(&t);
    return ((static_cast<uint64_t>(t.dwHighDateTime) << 32 | t.dwLowDateTime) - 116444736000000000ull) / 10000;
}
uint64_t Microseconds() {
    static LARGE_INTEGER frequency = [] {
        LARGE_INTEGER f{};
        QueryPerformanceFrequency(&f);
        return f;
    }();
    LARGE_INTEGER now{};
    QueryPerformanceCounter(&now);
    return static_cast<uint64_t>(now.QuadPart * 1000000 / frequency.QuadPart);
}
std::string JsonText(const std::string &text) {
    std::string out = "\"";
    for (unsigned char c : text) {
        if (c == '"' || c == '\\')
            out += '\\', out += static_cast<char>(c);
        else if (c < 0x20) {
            char buffer[8];
            sprintf_s(buffer, "\\u%04x", c);
            out += buffer;
        } else
            out += static_cast<char>(c);
    }
    return out + "\"";
}
// One monitor event: a log line, a line in BattlEyeFix.events.jsonl, and the status file's recent list.
// `fields` is a JSON fragment such as "\"player\":3,\"attempt\":1".
void Event(const std::string &kind, const std::string &fields, const std::string &line) {
    Write("BattlEye " + kind + ": " + line);
    auto json = "{\"atUtcMs\":" + std::to_string(UtcMs()) + ",\"kind\":" + JsonText(kind) +
                (fields.empty() ? "" : "," + fields) + "}";
    Log(directory, "BattlEyeFix.events.jsonl", json);
    std::lock_guard<std::mutex> lock(eventMutex);
    recentEvents.push_back(json);
    if (recentEvents.size() > 50)
        recentEvents.pop_front();
}
// Worker thread, every 5 s.
void ReadSettings() {
    RecheckSettings s;
    std::ifstream file(directory / L"BattlEyeFix.recheck");
    if (file) {
        s.hold = true;
        std::string line;
        while (std::getline(file, line)) {
            auto eq = line.find('=');
            if (eq == std::string::npos)
                continue;
            auto key = line.substr(0, eq);
            key.erase(std::remove_if(key.begin(), key.end(), [](unsigned char c) { return std::isspace(c); }),
                      key.end());
            long long value = 0;
            try {
                value = std::stoll(line.substr(eq + 1));
            } catch (...) {
                continue;
            }
            auto set = [&](int &field, long long lo, long long hi) {
                if (value >= lo && value <= hi)
                    field = static_cast<int>(value);
            };
            if (key == "hold")
                s.hold = value != 0;
            else if (key == "minReplyBytes")
                set(s.minReplyBytes, 1, 65536);
            else if (key == "replyWindowMs")
                set(s.replyWindowMs, 100, 60000);
            else if (key == "firstCheckSeconds")
                set(s.firstCheckSeconds, 10, 3600);
            else if (key == "retrySeconds")
                set(s.retrySeconds, 5, 3600);
            else if (key == "holdSeconds")
                set(s.holdSeconds, 10, 86400);
            else if (key == "degradedKicks")
                set(s.degradedKicks, 1, 1000);
            else if (key == "degradedWindowSeconds")
                set(s.degradedWindowSeconds, 30, 86400);
            else if (key == "notify")
                s.notify = value != 0;
        }
    }
    std::lock_guard<std::mutex> lock(settingsMutex);
    settings = s;
}
// Worker thread, every 5 s: BattlEyeFix.status.json, replaced in one step so a reader never sees half a file.
void WriteStatus() {
    auto s = CurrentSettings();
    std::ostringstream o;
    o << "{\n  \"updatedUtcMs\": " << UtcMs() << ",\n  \"startedUtcMs\": " << startedUtcMs
      << ",\n  \"monitor\": " << (beReceivedSlot ? "true" : "false")
      << ",\n  \"problem\": " << JsonText(recheckProblem)
      << ",\n  \"tracking\": " << (originalBeReceived ? "true" : "false")
      << ",\n  \"battlEye\": " << JsonText(beDegraded ? "degraded" : "healthy")
      << ",\n  \"recheck\": " << (s.hold ? "true" : "false") << ",\n  \"settings\": {\"minReplyBytes\": "
      << s.minReplyBytes << ", \"replyWindowMs\": " << s.replyWindowMs << ", \"firstCheckSeconds\": "
      << s.firstCheckSeconds << ", \"retrySeconds\": " << s.retrySeconds << ", \"holdSeconds\": " << s.holdSeconds
      << ", \"degradedKicks\": " << s.degradedKicks << ", \"degradedWindowSeconds\": " << s.degradedWindowSeconds
      << "},\n  \"counts\": {\"suspectedFalseKicks\": " << suspectedKicks << ", \"normalKicks\": " << normalKicks
      << ", \"held\": " << heldForRecheck << ", \"reregistrations\": " << reregistrations
      << ", \"passedAfterRecheck\": " << passedAfterRecheck << ", \"gaveUp\": " << gaveUp
      << ", \"dropped\": " << droppedRechecks << ", \"errors\": " << recheckErrors
      << ", \"joinChecksPassed\": " << joinChecksPassed << "},\n  \"lastSuspectedUtcMs\": " << lastSuspectedUtcMs
      << ",\n  \"lastDegradedUtcMs\": " << lastDegradedUtcMs << ",\n  \"lastRecoveredUtcMs\": " << lastRecoveredUtcMs
      << ",\n  \"lastStepUs\": " << lastStepUs << ",\n  \"maxStepUs\": " << maxStepUs << ",\n  \"recent\": [";
    {
        std::lock_guard<std::mutex> lock(eventMutex);
        bool first = true;
        for (auto &e : recentEvents) {
            o << (first ? "\n    " : ",\n    ") << e;
            first = false;
        }
    }
    o << "\n  ]\n}\n";
    auto text = o.str();
    auto temp = directory / L"BattlEyeFix.status.json.tmp";
    {
        std::ofstream out(temp, std::ios::binary | std::ios::trunc);
        out << text;
    }
    MoveFileExW(temp.c_str(), (directory / L"BattlEyeFix.status.json").c_str(), MOVEFILE_REPLACE_EXISTING);
}
// Every `call qword ptr [rip+X]` with X == slot.
std::vector<uintptr_t> CallsThroughSlot(uintptr_t slot) {
    std::vector<uintptr_t> found;
    for (auto section : engine.sections) {
        if (!section.executable)
            continue;
        std::vector<unsigned char> code(section.size);
        if (!Read(section.address, code.data(), code.size()))
            continue;
        for (size_t i = 0; i + 6 <= code.size(); ++i) {
            if (code[i] != 0xff || code[i + 1] != 0x15)
                continue;
            int32_t displacement{};
            memcpy(&displacement, &code[i + 2], 4);
            if (section.address + i + 6 + displacement == slot)
                found.push_back(section.address + i);
        }
    }
    return found;
}
uintptr_t FunctionOf(uintptr_t code) {
    DWORD64 base{};
    auto entry = RtlLookupFunctionEntry(code, &base, nullptr);
    if (!entry || base != engine.imageBase)
        return 0;
    return base + entry->BeginAddress;
}
// A reflected field by name, searching the object's class and its parents.
Property Member(uintptr_t object, const std::string &name) {
    std::set<uintptr_t> seen;
    for (auto klass = Get<uintptr_t>(object + 0x10); klass && seen.size() < 128 && seen.insert(klass).second;
         klass = Get<uintptr_t>(klass + 0x40))
        for (auto &p : Fields(klass))
            if (p.name == name)
                return p;
    Fail("member_not_found:" + name);
}
// Finds every piece and checks it against the code, so a game update leaves the monitor off.
void FindBattlEyeInterface() {
    const std::wstring text = L"BattlEyeServer: ServerOnReceivePacket with %u bytes from player %d";
    std::vector<unsigned char> pattern(reinterpret_cast<const unsigned char *>(text.c_str()),
                                       reinterpret_cast<const unsigned char *>(text.c_str()) +
                                           (text.size() + 1) * sizeof(wchar_t));
    auto strings = FindInSections(pattern, false);
    if (strings.size() != 1)
        Fail("receive_text_matches:" + std::to_string(strings.size()));
    std::vector<unsigned char> pointer(8);
    memcpy(pointer.data(), &strings[0], 8);
    std::set<uintptr_t> functions;
    for (auto record : FindInSections(pointer, false))
        for (auto lea : LeaRcxTo(record))
            if (auto f = FunctionOf(lea))
                functions.insert(f);
    if (functions.size() != 1)
        Fail("receive_function_matches:" + std::to_string(functions.size()));
    auto receive = *functions.begin();
    auto code = FunctionCode(receive);
    std::set<uintptr_t> slots;
    for (size_t i = 0; i + 6 <= code.size(); ++i)
        if (code[i] == 0xff && code[i + 1] == 0x15) {
            int32_t displacement{};
            memcpy(&displacement, &code[i + 2], 4);
            slots.insert(receive + i + 6 + displacement);
        }
    if (slots.size() != 1 || !InWritableData(*slots.begin()))
        Fail("received_slot_matches:" + std::to_string(slots.size()));
    auto received = *slots.begin();
    auto addPlayer = received - 0x20, status = received - 0x18;
    std::set<uintptr_t> registers;
    for (auto call : CallsThroughSlot(addPlayer))
        if (auto f = FunctionOf(call))
            registers.insert(f);
    if (registers.size() != 1)
        Fail("register_matches:" + std::to_string(registers.size()));
    if (!CodeMatches(*registers.begin(), {0x48, 0x89, 0x5c, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48, 0x89,
                                          0x7c, 0x24, 0x20, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57}))
        Fail("register_prologue_mismatch");
    std::set<uintptr_t> unregisters;
    for (auto call : CallsThroughSlot(status)) {
        unsigned char before[7]{};
        if (Read(call - 7, before, 7) && before[0] == 0xba && before[1] == 0xff && before[2] == 0xff &&
            before[3] == 0xff && before[4] == 0xff && before[5] == 0x8b && before[6] == 0xcf)
            if (auto f = FunctionOf(call))
                unregisters.insert(f);
    }
    if (unregisters.size() != 1)
        Fail("unregister_matches:" + std::to_string(unregisters.size()));
    auto unregister = *unregisters.begin();
    if (!CodeMatches(unregister, {0x48, 0x89, 0x5c, 0x24, 0x18, 0x56, 0x57, 0x41, 0x56, 0x48, 0x83, 0xec, 0x20, 0x48,
                                  0x8b, 0xd9}))
        Fail("unregister_prologue_mismatch");
    uintptr_t uniqueSet = 0;
    auto unregisterCode = FunctionCode(unregister);
    for (size_t i = 0; i + 7 <= unregisterCode.size() && !uniqueSet; ++i)
        if (unregisterCode[i] == 0x48 && unregisterCode[i + 1] == 0x8d && unregisterCode[i + 2] == 0x0d) {
            int32_t displacement{};
            memcpy(&displacement, &unregisterCode[i + 3], 4);
            if (InWritableData(unregister + i + 7 + displacement))
                uniqueSet = unregister + i + 7 + displacement;
        }
    if (!uniqueSet)
        Fail("unique_set_not_found");
    std::set<uintptr_t> adders;
    for (auto lea : LeaRcxTo(uniqueSet))
        if (auto f = FunctionOf(lea); f && f != *registers.begin() && f != unregister &&
                                      CodeMatches(f, {0x48, 0x89, 0x5c, 0x24, 0x18, 0x48, 0x89, 0x54, 0x24, 0x10, 0x55,
                                                      0x56, 0x57, 0x48, 0x83, 0xec, 0x30, 0x48, 0x8b, 0xf9}))
            adders.insert(f);
    if (adders.size() != 1)
        Fail("unique_adder_matches:" + std::to_string(adders.size()));
    beReceivedSlot = received;
    beAddPlayerSlot = addPlayer;
    beRegister = reinterpret_cast<BeRegister>(*registers.begin());
    beUnregister = reinterpret_cast<BeUnregister>(unregister);
    beAddUniqueId = reinterpret_cast<BeAddUniqueId>(*adders.begin());
    Write("BattlEye interface found: received slot " + Hex(received - engine.imageBase) + ", register " +
          Hex(*registers.begin() - engine.imageBase) + ", unregister " + Hex(unregister - engine.imageBase) +
          ", login step " + Hex(*adders.begin() - engine.imageBase));
}
// Game thread: every packet a player's BattlEye sends.
void BeReceivedHook(int player, const void *data, int size) {
    auto &trace = beTraces[player];
    // The first player after BattlEye loads is registered before this hook goes in; their first packet (about
    // 2 s later) stands in for the join time.
    if (!trace.registeredAt)
        trace.registeredAt = GetTickCount64();
    ++trace.packets;
    if (size > 2) { // 2-byte packets are acknowledgements
        trace.lastReplyAt = GetTickCount64();
        trace.lastReplyBytes = size;
        trace.largestReply = std::max(trace.largestReply, size);
    }
    originalBeReceived(player, data, size);
}
void BeAddPlayerHook(int player, unsigned long address, unsigned short port, const char *name) {
    beTraces[player] = BeTrace{GetTickCount64()};
    if (beRegistering) {
        beRegistering->pid = player;
        beRegistering->registered = true;
    }
    originalBeAddPlayer(player, address, port, name);
}
// Game thread: BattlEye fills its table when it loads, at the first player's join.
void InstallTableHooks() {
    auto received = reinterpret_cast<volatile uintptr_t *>(beReceivedSlot);
    auto added = reinterpret_cast<volatile uintptr_t *>(beAddPlayerSlot);
    // BattlEye's own code lives in its own module, never in the game's image.
    if (*received && *received != reinterpret_cast<uintptr_t>(&BeReceivedHook) &&
        !InExecutableSection(*received, true)) {
        originalBeReceived = reinterpret_cast<BeReceivedPacket>(*received);
        *received = reinterpret_cast<uintptr_t>(&BeReceivedHook);
        Write("BattlEye monitor: packet tracking on");
    }
    if (*added && *added != reinterpret_cast<uintptr_t>(&BeAddPlayerHook) && !InExecutableSection(*added, true)) {
        originalBeAddPlayer = reinterpret_cast<BeAddPlayer>(*added);
        *added = reinterpret_cast<uintptr_t>(&BeAddPlayerHook);
        Write("BattlEye monitor: registration tracking on");
    }
}
// Game thread, from the kick callback before the kick runs. True when this kick should be held for a re-check.
bool ClassifyKick(int player, const std::string &reason) {
    if (!beReceivedSlot)
        return false;
    auto s = CurrentSettings();
    auto now = GetTickCount64();
    auto found = beTraces.find(player);
    BeTrace trace = found != beTraces.end() ? found->second : BeTrace{};
    if (found != beTraces.end())
        found->second.kicked = true;
    bool traced = trace.registeredAt != 0;
    long long sinceRegister = traced ? static_cast<long long>(now - trace.registeredAt) : -1;
    long long sinceReply = trace.lastReplyAt ? static_cast<long long>(now - trace.lastReplyAt) : -1;
    bool notResponding = reason.find("not responding") != std::string::npos;
    bool answered = trace.lastReplyAt && trace.lastReplyBytes >= s.minReplyBytes && sinceReply <= s.replyWindowMs;
    bool joinCheck = traced && sinceRegister <= static_cast<long long>(s.firstCheckSeconds) * 1000;
    bool suspected = notResponding && answered && joinCheck;
    auto fields = "\"player\":" + std::to_string(player) + ",\"reason\":" + JsonText(reason) +
                  ",\"msSinceRegister\":" + std::to_string(sinceRegister) +
                  ",\"msSinceReply\":" + std::to_string(sinceReply) +
                  ",\"lastReplyBytes\":" + std::to_string(trace.lastReplyBytes) +
                  ",\"packets\":" + std::to_string(trace.packets) + ",\"suspectedFalse\":" + (suspected ? "true" : "false");
    auto line = "player " + std::to_string(player) + " (" + reason + "), " +
                (traced ? std::to_string(sinceRegister) + " ms after joining" : "join not traced") + ", last reply " +
                (trace.lastReplyAt ? std::to_string(trace.lastReplyBytes) + " bytes " + std::to_string(sinceReply) +
                                         " ms before"
                                   : "none");
    if (!suspected) {
        ++normalKicks;
        Event("kick", fields, line + ": normal kick");
        return false;
    }
    ++suspectedKicks;
    lastSuspectedUtcMs = UtcMs();
    suspectedTimes.push_back(now);
    while (!suspectedTimes.empty() && now - suspectedTimes.front() > static_cast<uint64_t>(s.degradedWindowSeconds) * 1000)
        suspectedTimes.pop_front();
    Event("suspected false kick", fields,
          line + ": the player's BattlEye answered, so BattlEye's verdict looks wrong" +
              (s.hold ? "" : " (re-check off, kicking as normal)"));
    if (!beDegraded && static_cast<int>(suspectedTimes.size()) >= s.degradedKicks) {
        beDegraded = true;
        lastDegradedUtcMs = UtcMs();
        Event("degraded",
              "\"suspectedKicks\":" + std::to_string(suspectedTimes.size()) +
                  ",\"windowSeconds\":" + std::to_string(s.degradedWindowSeconds),
              std::to_string(suspectedTimes.size()) + " suspected false kicks in " +
                  std::to_string(s.degradedWindowSeconds) + " s: BattlEye's checks look broken");
    }
    if (!s.hold || !beRegister || !beUnregister || !beAddUniqueId || !originalKickPlayer)
        return false;
    for (auto &item : rechecks)
        if (item.pid == player && now - item.firstAt > static_cast<uint64_t>(s.holdSeconds) * 1000) {
            ++gaveUp;
            Event("re-check gave up", "\"player\":" + std::to_string(player) + ",\"attempts\":" + std::to_string(item.attempts),
                  "player " + std::to_string(player) + " still failing after " + std::to_string(item.attempts) +
                      " re-check(s) and " + std::to_string(s.holdSeconds) + " s, kicking");
            item.pid = -2; // removed by the tick
            return false;
        }
    return true;
}
// Game thread, from KickPlayerHook during a suspected kick: hold the player instead of kicking.
void HoldForRecheck(void *controller, int player) {
    auto s = CurrentSettings();
    auto handle = Ref(reinterpret_cast<uintptr_t>(controller));
    for (auto &item : rechecks)
        if (item.pid == player || (item.controller.index == handle.index && item.controller.serial == handle.serial)) {
            item.unregistered = item.registered = false; // failed again: next attempt from this registration
            item.pid = player;
            return;
        }
    if (rechecks.size() >= 64)
        Fail("too_many_rechecks");
    Recheck item;
    item.controller = handle;
    item.pid = player;
    item.firstAt = GetTickCount64();
    rechecks.push_back(item);
    ++heldForRecheck;
    if (s.notify)
        try {
            SendMessageBox(reinterpret_cast<uintptr_t>(controller), "BattlEye check failed on BattlEye's side",
                           "BattlEye's servers rejected a normal check (\"Client not responding\"). This happens to "
                           "many players when BattlEye is having problems.\n\nYou won't be kicked for now. The server "
                           "will ask BattlEye to check you again in about " +
                               std::to_string(s.retrySeconds) + " seconds. You don't need to do anything.");
        } catch (...) {
        }
}
// ConanSandbox players, by the unique net id the game's BattlEye functions take.
const void *UniqueIdOf(uintptr_t controller) {
    auto statePointer = Member(controller, "PlayerState");
    if (statePointer.type != "ObjectProperty")
        Fail("player_state_type:" + statePointer.type);
    auto state = Get<uintptr_t>(controller + statePointer.offset);
    if (!state)
        Fail("no_player_state");
    RequireClass(state, "PlayerState");
    auto unique = Member(state, "UniqueID"); // FUniqueNetIdRepl, 48 bytes in this build
    if (unique.type != "StructProperty" || unique.size != 48)
        Fail("unique_id_layout:" + unique.type + "/" + std::to_string(unique.size));
    return reinterpret_cast<const void *>(state + unique.offset);
}
template <class Step> uint64_t Timed(Step step) {
    auto began = Microseconds();
    step();
    auto spent = Microseconds() - began;
    lastStepUs = spent;
    if (spent > maxStepUs)
        maxStepUs = spent;
    return spent;
}
// Game thread, every tick while there is anything to do.
void RecheckTick() {
    InstallTableHooks();
    auto s = CurrentSettings();
    auto now = GetTickCount64();
    for (auto it = beTraces.begin(); it != beTraces.end();) {
        auto &trace = it->second;
        if (!trace.passed && !trace.kicked && trace.registeredAt &&
            now - trace.registeredAt > static_cast<uint64_t>(s.firstCheckSeconds) * 1000) {
            trace.passed = true;
            if (trace.largestReply >= s.minReplyBytes) {
                ++joinChecksPassed;
                for (auto &item : rechecks)
                    if (item.pid == it->first) {
                        ++passedAfterRecheck;
                        Event("re-check passed",
                              "\"player\":" + std::to_string(it->first) + ",\"attempts\":" + std::to_string(item.attempts),
                              "player " + std::to_string(it->first) + " passed BattlEye's check after " +
                                  std::to_string(item.attempts) + " re-check(s), protected again");
                        item.pid = -3;
                    }
                if (beDegraded) {
                    beDegraded = false;
                    lastRecoveredUtcMs = UtcMs();
                    suspectedTimes.clear();
                    Event("recovered", "\"player\":" + std::to_string(it->first),
                          "a player passed BattlEye's join check again");
                }
            }
        }
        if (trace.kicked || (trace.passed && now - trace.registeredAt > 3600000))
            it = beTraces.erase(it);
        else
            ++it;
    }
    for (auto it = rechecks.begin(); it != rechecks.end();) {
        if (it->pid == -2 || it->pid == -3) {
            it = rechecks.erase(it);
            continue;
        }
        try {
            auto controller = Resolve(it->controller);
            if (!it->unregistered) {
                auto id = UniqueIdOf(controller);
                auto spent = Timed([&] { beUnregister(id); });
                it->unregistered = true;
                it->unregisteredAt = now;
                Write("BattlEye re-check: player taken off BattlEye in " + std::to_string(spent) +
                      " us, registering again in " + std::to_string(s.retrySeconds) + " s");
            } else if (!it->registered && now - it->unregisteredAt >= static_cast<uint64_t>(s.retrySeconds) * 1000) {
                auto id = UniqueIdOf(controller);
                beRegistering = &*it;
                auto spent = Timed([&] {
                    // Put back the login entry unregister removed (so the next unregister, or the player's
                    // logout, finds them), then register as the game does when a player possesses a character.
                    beAddUniqueId(id, reinterpret_cast<void *>(controller));
                    beRegister(reinterpret_cast<void *>(controller));
                });
                beRegistering = nullptr;
                ++it->attempts;
                ++reregistrations;
                if (!it->registered)
                    Fail("register_did_not_add_player");
                Event("re-registered",
                      "\"player\":" + std::to_string(it->pid) + ",\"attempt\":" + std::to_string(it->attempts) +
                          ",\"us\":" + std::to_string(spent),
                      "registered again as player " + std::to_string(it->pid) + " in " + std::to_string(spent) +
                          " us (attempt " + std::to_string(it->attempts) + "), waiting for a fresh check");
            }
            ++it;
        } catch (const std::exception &e) {
            beRegistering = nullptr;
            std::string why = e.what();
            if (why.find("stale_object_handle") != std::string::npos || why.find("object_pending_gc") != std::string::npos) {
                ++droppedRechecks;
                Write("BattlEye re-check dropped: the player left");
            } else {
                ++recheckErrors;
                Write("BattlEye re-check failed, dropping it: " + why);
            }
            it = rechecks.erase(it);
        }
    }
}
bool RecheckBusy() {
    return beReceivedSlot && (!originalBeReceived || !originalBeAddPlayer || !beTraces.empty() || !rechecks.empty());
}

// ProcessEvent passes straight through; actor ticks on the game thread drive the held kicks.
void EventHook(void *object, void *function, void *parameters) {
    thread_local int depth = 0;
    ++depth;
    originalEvent(object, function, parameters);
    --depth;
    if (!depth && function && GetCurrentThreadId() == gameThreadId && (!heldKicks.empty() || RecheckBusy()) &&
        *reinterpret_cast<const uint32_t *>(reinterpret_cast<uintptr_t>(function) + 0x18) == receiveTickName &&
        OnGameThread()) {
        if (!heldKicks.empty())
            HeldKickTick();
        // ReceiveTick runs for many actors per frame; the re-check runs at most every 50 ms.
        static uint64_t lastRecheck = 0;
        auto now = GetTickCount64();
        if (RecheckBusy() && now - lastRecheck >= 50) {
            lastRecheck = now;
            RecheckTick();
        }
    }
}
// Worker thread: once the world is up, confirms the guard can work and hooks KickPlayer for the message.
void ReportReady() {
    static bool reported = false, failureReported = false;
    if (reported)
        return;
    try {
        uintptr_t gameSession = 0;
        ValidatedInstance(&gameSession);
        reported = true;
        Write("Guard ready: game instance > world > ConanGameMode > GameSession validated");
        if (!sessionKickSlot || !originalEvent || !receiveTickName)
            return;
        auto kick = Get<uintptr_t>(Get<uintptr_t>(gameSession) + sessionKickSlot);
        if (!InExecutableSection(kick, true))
            Write("Kick message disabled: KickPlayer outside code");
        else if (MH_CreateHook(reinterpret_cast<void *>(kick), reinterpret_cast<void *>(&KickPlayerHook),
                               reinterpret_cast<void **>(&originalKickPlayer)) != MH_OK ||
                 MH_EnableHook(reinterpret_cast<void *>(kick)) != MH_OK) {
            originalKickPlayer = nullptr;
            Write("Kick message disabled: KickPlayer hook failed");
        } else
            Write("Kick message armed: players see why, then are kicked " + std::to_string(kickDelayMs / 1000) +
                  " s later");
    } catch (const std::exception &e) {
        if (!failureReported) {
            failureReported = true;
            Write(std::string("Guard waiting for the world to load: ") + e.what());
        }
    }
}

DWORD WINAPI Run(void *) {
    try {
        directory = ModuleDirectory(self);
        Write("BattlEyeFix starting");
        if (FileExists(L"BattlEyeFix.disabled")) {
            Write("BattlEyeFix.disabled found: patch off, server runs unchanged");
            return 0;
        }
        auto hash = HashExecutable();
        if (hash != approvedExecutable) {
            Write("Server executable is not Steam build 26552396 (SHA-256 " + hash +
                  "): patch off, server runs unchanged");
            return 0;
        }
        // Let the engine set up its object registry. Players can't join for minutes yet.
        Sleep(30000);
        DiscoverEngine();
        DiscoverGameThread();
        IndexClasses();
        FindBattlEyeKick();
        try {
            RefreshInstance();
        } catch (...) {
        }
        auto status = MH_Initialize();
        if (status != MH_OK)
            Fail("minhook_initialize:" + std::to_string(status));
        if (MH_CreateHook(reinterpret_cast<void *>(battlEyeKickCode), reinterpret_cast<void *>(&BattlEyeKickHook),
                          reinterpret_cast<void **>(&originalBattlEyeKick)) != MH_OK ||
            MH_EnableHook(reinterpret_cast<void *>(battlEyeKickCode)) != MH_OK)
            Fail("battleye_kick_hook_failed");
        Write("Guard armed: a BattlEye kick can no longer crash the server");
        startedUtcMs = UtcMs();
        ReadSettings();
        try {
            FindBattlEyeInterface();
            Write(std::string("BattlEye monitor armed; re-check ") +
                  (CurrentSettings().hold ? "on: suspected false kicks are held and re-checked"
                                          : "off (create BattlEyeFix.recheck to turn it on)"));
        } catch (const std::exception &e) {
            recheckProblem = e.what();
            beReceivedSlot = 0;
            Write(std::string("BattlEye monitor off: ") + e.what());
        }
        try {
            receiveTickName = Get<uint32_t>(FindFunction(Class("Actor"), "ReceiveTick").address + 0x18);
            if (MH_CreateHook(reinterpret_cast<void *>(engine.processEvent), reinterpret_cast<void *>(&EventHook),
                              reinterpret_cast<void **>(&originalEvent)) != MH_OK ||
                MH_EnableHook(reinterpret_cast<void *>(engine.processEvent)) != MH_OK) {
                originalEvent = nullptr;
                Fail("process_event_hook_failed");
            }
        } catch (const std::exception &e) {
            receiveTickName = 0;
            Write(std::string("Kick message disabled: ") + e.what());
        }
        for (uint64_t tick = 0;; ++tick) {
            Sleep(250);
            noticeOff = FileExists(L"BattlEyeFix.notice-off");
            if (tick % 20 == 0) {
                ReadSettings();
                try {
                    WriteStatus();
                } catch (...) {
                }
            }
            if (tick % 40 == 20)
                try {
                    RefreshInstance();
                    ReportReady();
                } catch (...) {
                }
        }
    } catch (const std::exception &e) {
        Write(std::string("Patch off, server runs unchanged: ") + e.what());
    } catch (...) {
        Write("Patch off, server runs unchanged: unexpected failure");
    }
    return 0;
}
} // namespace

// ---------------------------------------------------------------------------------------------------------
// winmm.dll proxy. DllMain only records our handle; the patch starts on the first forwarded call.
static INIT_ONCE systemOnce = INIT_ONCE_STATIC_INIT;
static INIT_ONCE patchOnce = INIT_ONCE_STATIC_INIT;
static HMODULE systemWinmm;
static decltype(&timeGetTime) realTimeGetTime;
static decltype(&timeBeginPeriod) realTimeBeginPeriod;
static decltype(&timeEndPeriod) realTimeEndPeriod;

static BOOL CALLBACK ResolveSystem(PINIT_ONCE, PVOID, PVOID *) {
    wchar_t path[32768]{};
    auto n = GetSystemDirectoryW(path, ARRAYSIZE(path));
    if (!n || n >= ARRAYSIZE(path) - 11)
        return FALSE;
    wcscat_s(path, L"\\winmm.dll");
    auto module = LoadLibraryExW(path, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module)
        return FALSE;
    systemWinmm = module;
    realTimeGetTime = reinterpret_cast<decltype(realTimeGetTime)>(GetProcAddress(module, "timeGetTime"));
    realTimeBeginPeriod = reinterpret_cast<decltype(realTimeBeginPeriod)>(GetProcAddress(module, "timeBeginPeriod"));
    realTimeEndPeriod = reinterpret_cast<decltype(realTimeEndPeriod)>(GetProcAddress(module, "timeEndPeriod"));
    return realTimeGetTime && realTimeBeginPeriod && realTimeEndPeriod;
}
static BOOL CALLBACK QueuePatch(PINIT_ONCE, PVOID, PVOID *) {
    // No wait: safe even if the caller is another module's initialization routine.
    auto thread = CreateThread(nullptr, 0, Run, nullptr, 0, nullptr);
    if (!thread)
        return FALSE;
    CloseHandle(thread);
    return TRUE;
}
static void EnsureReady() {
    if (!InitOnceExecuteOnce(&systemOnce, ResolveSystem, nullptr, nullptr))
        RaiseFailFastException(nullptr, nullptr, 0); // cannot emulate a missing Windows timer
    InitOnceExecuteOnce(&patchOnce, QueuePatch, nullptr, nullptr);
}
extern "C" DWORD WINAPI ProxyTimeGetTime() {
    EnsureReady();
    return realTimeGetTime();
}
extern "C" MMRESULT WINAPI ProxyTimeBeginPeriod(UINT period) {
    EnsureReady();
    return realTimeBeginPeriod(period);
}
extern "C" MMRESULT WINAPI ProxyTimeEndPeriod(UINT period) {
    EnsureReady();
    return realTimeEndPeriod(period);
}
#define FORWARD(name, signature, arguments)                                                                            \
    extern "C" MMRESULT WINAPI Proxy_##name signature {                                                                \
        EnsureReady();                                                                                                 \
        static auto fn = reinterpret_cast<decltype(&name)>(GetProcAddress(systemWinmm, #name));                        \
        if (!fn)                                                                                                       \
            RaiseFailFastException(nullptr, nullptr, 0);                                                               \
        return fn arguments;                                                                                           \
    }
FORWARD(waveOutGetDevCapsW, (UINT_PTR a, LPWAVEOUTCAPSW b, UINT c), (a, b, c))
FORWARD(mixerSetControlDetails, (HMIXEROBJ a, LPMIXERCONTROLDETAILS b, DWORD c), (a, b, c))
FORWARD(mixerGetControlDetailsA, (HMIXEROBJ a, LPMIXERCONTROLDETAILS b, DWORD c), (a, b, c))
FORWARD(mixerGetLineControlsA, (HMIXEROBJ a, LPMIXERLINECONTROLSA b, DWORD c), (a, b, c))
FORWARD(mixerGetID, (HMIXEROBJ a, LPUINT b, DWORD c), (a, b, c))
FORWARD(mixerGetLineInfoA, (HMIXEROBJ a, LPMIXERLINEA b, DWORD c), (a, b, c))
FORWARD(mixerClose, (HMIXER a), (a))
FORWARD(mixerOpen, (LPHMIXER a, UINT b, DWORD_PTR c, DWORD_PTR d, DWORD e), (a, b, c, d, e))
FORWARD(mixerGetDevCapsA, (UINT_PTR a, LPMIXERCAPSA b, UINT c), (a, b, c))
FORWARD(waveInMessage, (HWAVEIN a, UINT b, DWORD_PTR c, DWORD_PTR d), (a, b, c, d))
FORWARD(waveInClose, (HWAVEIN a), (a))
FORWARD(waveInOpen, (LPHWAVEIN a, UINT b, LPCWAVEFORMATEX c, DWORD_PTR d, DWORD_PTR e, DWORD f), (a, b, c, d, e, f))
FORWARD(waveOutMessage, (HWAVEOUT a, UINT b, DWORD_PTR c, DWORD_PTR d), (a, b, c, d))
FORWARD(waveOutClose, (HWAVEOUT a), (a))
FORWARD(waveOutOpen, (LPHWAVEOUT a, UINT b, LPCWAVEFORMATEX c, DWORD_PTR d, DWORD_PTR e, DWORD f), (a, b, c, d, e, f))
FORWARD(timeKillEvent, (UINT a), (a))
FORWARD(timeSetEvent, (UINT a, UINT b, LPTIMECALLBACK c, DWORD_PTR d, UINT e), (a, b, c, d, e))
#undef FORWARD
BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH)
        self = module;
    return TRUE;
}
