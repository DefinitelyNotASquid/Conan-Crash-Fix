#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <filesystem>
#include <string>
#include <windows.h>

inline std::filesystem::path ModuleDirectory(HMODULE module) {
    wchar_t path[32768]{};
    auto n = GetModuleFileNameW(module, path, ARRAYSIZE(path));
    if (!n || n == ARRAYSIZE(path))
        return {};
    return std::filesystem::path(path).parent_path();
}
inline void Log(const std::filesystem::path &directory, const char *file, const std::string &message) {
    auto handle = CreateFileW((directory / file).c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE)
        return;
    SYSTEMTIME time{};
    GetSystemTime(&time);
    char prefix[100]{};
    sprintf_s(prefix, "%04u-%02u-%02uT%02u:%02u:%02uZ pid=%lu ", time.wYear, time.wMonth, time.wDay, time.wHour,
              time.wMinute, time.wSecond, GetCurrentProcessId());
    auto line = std::string(prefix) + message + "\r\n";
    DWORD written{};
    WriteFile(handle, line.data(), static_cast<DWORD>(line.size()), &written, nullptr);
    CloseHandle(handle);
}
