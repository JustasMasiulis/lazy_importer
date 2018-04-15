#include "include/lazy_importer.hpp"
#include <Windows.h>

int main()
{
    const auto base = LI_GET(LoadLibraryA)("user32.dll");
    LI_GET(MessageBoxA)(nullptr, "asd", "asd", 0);
}
