#include "include/lazy_importer.hpp"
#include <Windows.h>

int main()
{
    const auto base =
        reinterpret_cast<std::uintptr_t>(LI_FIND(LoadLibraryA)("user32.dll"));
    LI_GET(base, MessageBoxA)(nullptr, "asd", "asd", 0);
    auto status = LI_NT(NtClose)(nullptr);
}
