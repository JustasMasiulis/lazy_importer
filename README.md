# lazy importer
A simple and easy to use header only library to make the life of a reverse engineer much harder.

## small example
```cpp
LI_FIND(MessageBoxA)(nullptr, "hello world", nullptr, 0);
```

## Features
* Does not leave any strings in memory.
* Does not allocate any memory.
* Can be easily inlined.
* Does not import any functions.
* Produces extremely small assembly.
* Non caching functions do not leave anything in data sections.

## A thing to take consideration of
You must be sure that the function you are trying to find is exported and the shared library is loaded.
If that is not the case your program _will_ crash.

## Example output
Example from above decompiled with ida when forcefully not inlined
```c
char *sub_1400010D0()
{
  // variable declarations

  for ( i = *(_QWORD **)(*(_QWORD *)(*(_QWORD *)(__readgsqword(0x30u) + 96) + 24i64) + 16i64); ; i = (_QWORD *)*i )
  {
    v1 = (_DWORD *)i[6];
    v2 = (_DWORD *)((char *)v1 + *(unsigned int *)((char *)v1 + v1[15] + 136));
    if ( v2 != v1 )
    {
      v3 = 0i64;
      if ( v2[6] )
        break;
    }
LABEL_9:
    ;
  }
  v4 = (_DWORD *)((char *)v1 + (unsigned int)v2[8]);
  while ( 1 )
  {
    v5 = -2128831035;
    v6 = (char *)v1 + *v4;
    v7 = *v6;
    if ( *v6 )
    {
      do
      {
        ++v6;
        v5 = 16777619 * (v5 ^ v7);
        v7 = *v6;
      }
      while ( *v6 );
      if ( v5 == 598309348 )
        return (char *)v1
             + *(unsigned int *)((char *)&v1[*(unsigned __int16 *)((char *)v1 + 2 * v3 + (unsigned int)v2[9])]
                               + (unsigned int)v2[7]);
    }
    v3 = (unsigned int)(v3 + 1);
    ++v4;
    if ( (unsigned int)v3 >= v2[6] )
      goto LABEL_9;
  }
}
```

## Documentation
lazy importer exposes 5 rather self explanatory macros.

2 of those macros have _CACHED counterparts that take use of static variables 
and templates to cache the results for faster execution of subsequent calls to same function.

`LI_FIND[_CACHED)](function)`
Iterates trough all modules and their exports.

`LI_NT[_CACHED](function)`
Iterates trough `ntdll.dll` exports.

`LI_GET(module_base_address, function)`
Iterates trough exports of given module.

None of these functions throw exceptions and are linear in complexity.

## Extra configuration
define LAZY_IMPORTER_NO_FORCEINLINE to disable force inlining

define LAZY_IMPORTER_WINDOWS_INCLUDE_DIR with your files include path not to use <Windows.h> and <Winternl.h>
