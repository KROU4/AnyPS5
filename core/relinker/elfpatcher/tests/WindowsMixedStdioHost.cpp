#include <windows.h>
#include <cstdio>
#include <cstdlib>

namespace {

struct LegacyFile {
    char* ptr;
    int count;
    char* base;
    int flags;
    int file;
    int charbuf;
    int bufferSize;
    char* tempName;
};

static_assert(sizeof(LegacyFile) == 48);
const bool directoryChanged = [] {
    wchar_t path[32768];
    const auto length = GetModuleFileNameW(nullptr, path, 32768);
    if (length == 0 || length >= 32768) return false;
    auto separator = length;
    while (separator != 0 && path[separator - 1] != L'\\') --separator;
    if (separator == 0 || separator + 3 >= 32768) return false;
    path[separator] = L'p';
    path[separator + 1] = L'r';
    path[separator + 2] = L'x';
    path[separator + 3] = 0;
    return SetCurrentDirectoryW(path) != 0;
}();

}

extern "C" int shared() {
    if (!directoryChanged) std::abort();
    const auto legacyModule = GetModuleHandleW(L"msvcrt.dll");
    if (!legacyModule) std::abort();
    const auto putsFunction = reinterpret_cast<int (*)(const char*, LegacyFile*)>(GetProcAddress(legacyModule, "fputs"));
    const auto flushFunction = reinterpret_cast<int (*)(LegacyFile*)>(GetProcAddress(legacyModule, "fflush"));
    if (!putsFunction || !flushFunction) std::abort();
    auto* streams = reinterpret_cast<LegacyFile*>(__iob_func());
    std::fputs("Windows DLL stdout probe UCRT\n", stdout);
    std::fflush(stdout);
    putsFunction("Windows DLL stdout probe MSVCRT\n", streams + 1);
    flushFunction(streams + 1);
    std::fputs("Windows DLL stderr probe UCRT\n", stderr);
    std::fflush(stderr);
    putsFunction("Windows DLL stderr probe MSVCRT\n", streams + 2);
    flushFunction(streams + 2);
    return 11;
}
