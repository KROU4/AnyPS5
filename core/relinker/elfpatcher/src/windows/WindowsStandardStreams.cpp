#include <elfpatcher/windows/WindowsStandardStreams.hpp>
#include <codegen/x86/X64Assembler.hpp>
#include <io/BufferUtils.hpp>

namespace Elfpatcher::Windows {

WindowsStandardStreams::WindowsStandardStreams(PeSection& data) {
    for (const auto& name : {"msvcrt.dll", "__iob_func", "_fileno", "_get_osfhandle", "_wfreopen", "_open_osfhandle", "_dup2", "_close"}) {
        storage.emplace(name, CheckedRva(data.Rva + data.Data.size()));
        Io::AppendString(data.Data, name);
    }
    for (const auto& [name, text] : std::map<std::string, std::u16string>{{"mode", u"a"}}) {
        Io::AlignBuffer(data.Data, 2);
        storage.emplace(name, CheckedRva(data.Rva + data.Data.size()));
        for (const auto unit : text) Io::AppendU16(data.Data, unit);
        Io::AppendU16(data.Data, 0);
    }
    Io::AlignBuffer(data.Data, 8);
    for (const auto& name : {"module", "stream", "source", "duplicate", "descriptor", "status", "iob", "fileno", "handle", "reopen", "open", "dup2", "close"}) {
        storage.emplace(name, CheckedRva(data.Rva + data.Data.size()));
        data.Data.resize(data.Data.size() + 8);
    }
}

std::vector<std::size_t> WindowsStandardStreams::Initialize(WindowsStubEmitter& code, const WindowsImports& imports, const std::uint32_t logHandle, const std::uint32_t logPath) const {
    using enum Codegen::X64Register;
    Codegen::X64Assembler a(code, imports.Functions, storage);
    std::vector<std::size_t> failures;
    code.Rip({0x48, 0x8b, 0x05}, logHandle);
    a.Test(Ax);
    a.Jump("done", 0x84);
    a.Data(Cx, "msvcrt.dll");
    a.Api("GetModuleHandleA");
    a.Test(Ax);
    a.Jump("done", 0x84);
    a.Save("module", Ax);
    for (const auto& [name, target] : std::map<std::string, std::string>{{"__iob_func", "iob"}, {"_fileno", "fileno"}, {"_get_osfhandle", "handle"}, {"_wfreopen", "reopen"}, {"_open_osfhandle", "open"}, {"_dup2", "dup2"}, {"_close", "close"}}) {
        a.Global(Cx, "module");
        a.Data(Dx, name);
        a.Api("GetProcAddress");
        a.Test(Ax);
        failures.push_back(code.Branch({0x0f, 0x84}));
        a.Save(target, Ax);
    }
    for (const auto index : {1u, 2u}) {
        const auto suffix = std::to_string(index);
        code.Rip({0xff, 0x15}, storage.at("iob"));
        a.AddValue(Ax, index * 48u);
        a.Save("stream", Ax);
        a.Mov(Cx, Ax);
        code.Rip({0xff, 0x15}, storage.at("fileno"));
        code.Emit({0x85, 0xc0});
        a.Jump("reopen" + suffix, 0x88);
        a.Mov(Cx, Ax);
        code.Rip({0xff, 0x15}, storage.at("handle"));
        a.Test(Ax);
        a.Jump("reopen" + suffix, 0x84);
        a.Jump("next" + suffix, 0x89);
        a.Mark("reopen" + suffix);
        const auto standardHandle = index == 1u ? 0xfffffff5u : 0xfffffff4u;
        code.Emit({0xb9});
        code.U32(standardHandle);
        a.Api("GetStdHandle");
        a.Save("source", Ax);
        code.Rip({0x48, 0x8d, 0x0d}, logPath);
        a.Data(Dx, "mode");
        a.Global(R8, "stream");
        code.Rip({0xff, 0x15}, storage.at("reopen"));
        a.Test(Ax);
        failures.push_back(code.Branch({0x0f, 0x84}));
        a.Value(Cx, ~std::uint64_t{});
        a.Global(Dx, "source");
        a.Value(R8, ~std::uint64_t{});
        a.Data(R9, "duplicate");
        a.Value(Ax, 0);
        a.Store(Sp, 0x20, Ax);
        a.Store(Sp, 0x28, Ax);
        a.Value(Ax, 2);
        a.Store(Sp, 0x30, Ax);
        a.Api("DuplicateHandle");
        a.Test(Ax);
        failures.push_back(code.Branch({0x0f, 0x84}));
        a.Global(Cx, "duplicate");
        a.Value(Dx, 0x4001);
        code.Rip({0xff, 0x15}, storage.at("open"));
        code.Emit({0x85, 0xc0});
        a.Jump("opened" + suffix, 0x89);
        a.Global(Cx, "duplicate");
        a.Api("CloseHandle");
        failures.push_back(code.Branch({0xe9}));
        a.Mark("opened" + suffix);
        a.Save("descriptor", Ax);
        a.Global(Cx, "stream");
        code.Rip({0xff, 0x15}, storage.at("fileno"));
        a.Mov(Dx, Ax);
        a.Global(Cx, "descriptor");
        code.Rip({0xff, 0x15}, storage.at("dup2"));
        a.Save("status", Ax);
        a.Global(Cx, "descriptor");
        code.Rip({0xff, 0x15}, storage.at("close"));
        a.Test(Ax);
        failures.push_back(code.Branch({0x0f, 0x85}));
        a.Global(Ax, "status");
        a.Test(Ax);
        failures.push_back(code.Branch({0x0f, 0x85}));
        a.Global(Dx, "source");
        code.Emit({0xb9});
        code.U32(standardHandle);
        a.Api("SetStdHandle");
        a.Test(Ax);
        failures.push_back(code.Branch({0x0f, 0x84}));
        a.Mark("next" + suffix);
    }
    a.Mark("done");
    a.Finish();
    return failures;
}

}
