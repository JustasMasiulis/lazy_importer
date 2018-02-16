#include <Windows.h>
#include "include/lazy_importer.hpp"


int main()
{
    const auto base = LI_LOAD("user32.dll");
    //   LI_LAZY(MessageBoxA)(nullptr, "asd", "asd", 0);
}
