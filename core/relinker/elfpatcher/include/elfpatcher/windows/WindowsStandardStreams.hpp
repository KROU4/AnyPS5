#ifndef ELFPATCHER_WINDOWS_STANDARDSTREAMS_HPP
#define ELFPATCHER_WINDOWS_STANDARDSTREAMS_HPP

#include <elfpatcher/windows/WindowsImportBuilder.hpp>
#include <elfpatcher/windows/WindowsStubEmitter.hpp>
#include <map>

namespace Elfpatcher::Windows {

class WindowsStandardStreams {
public:
    explicit WindowsStandardStreams(PeSection& data);
    std::vector<std::size_t> Initialize(WindowsStubEmitter& code, const WindowsImports& imports, std::uint32_t logHandle, std::uint32_t logPath) const;

private:
    std::map<std::string, std::uint32_t> storage;
};

}

#endif
