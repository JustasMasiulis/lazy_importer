#define LAZY_IMPORTER_CASE_INSENSITIVE
#include "include/lazy_importer.hpp"

int main()
{
    decltype(LoadLibraryA) LoAdLiBrArYa;
    LI_FIND_CACHED(LoAdLiBrArYa)("user32.dll");
    // LI_FIND(MessageBoxA)(nullptr, "adasdasd", "asdasd", 0);
}
