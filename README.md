# lazy importer [![](https://img.shields.io/badge/version-2.0.1-green.svg)]()

A simple and easy to use header only library to make the life of a reverse engineer much harder.

## small example

```cpp
LI_FN(OutputDebugStringA)("hello world");
LI_FN(VirtualProtect).in(LI_MODULE("kernel32.dll").cached());
```

[IDA output when compiling first line](#example-output)

## features

- Does not leave any strings in memory.
- Does not allocate any memory.
- Can be easily inlined.
- Does not leave any imports in the executable.
- Produces extremely small assembly.
- Non caching functions do not leave anything in data sections.

## documentation

- `LI_FN(function_pointer) -> lazy_function`
- `LI_FN_DEF(function_type) -> lazy_function`
- `LI_MODULE(module_name) -> lazy_module`

#### **`lazy_module`**

| function                 | explanation                                                                  |
| ------------------------ | ---------------------------------------------------------------------------- |
| `get<T = void*>`         | returns address of module. If module does not exist behavior is not defined. |
| `safe<T = void*>`        | returns address of module. If module does not exist returns 0.               |
| `cached<T = void*>`      | same as `get` except the result is cached.                                   |
| `safe_cached<T = void*>` | same as `safe` except the result is cached.                                  |

#### **`lazy_function`**

Shares API with lazy_module except it returns the address of function with these additions:

- has overloaded `operator()` which acquires function using `get` and calls it
  with provided arguments.
- `forwarded`, `forwarded_safe`, `forwarded_cached`, `forwarded_safe_cached` same as `get` with the addition of ability to resolve forwarded exports.
- `in`, `in_safe`, `in_cached`, `in_safe_cached` same functionality as `get`, but the search is done in a single module whose base address is the first parameter.
- `nt`, `nt_safe`, `nt_cached`, `nt_safe_cached` same as `in(LI_MODULE("ntdll.dll).get())`.

#### extra configuration

| `#define`                                 | description                                                                             |
| ----------------------------------------- | --------------------------------------------------------------------------------------- |
| `LAZY_IMPORTER_NO_FORCEINLINE`            | disables force inlining                                                                 |
| `LAZY_IMPORTER_CASE_INSENSITIVE`          | enables case insensitive comparison. Might be required for forwarded export resolution. |
| `LAZY_IMPORTER_CACHE_OPERATOR_PARENS`     | uses `cached()` instead of `get()` in `operator()` of lazy_function                     |
| `LAZY_IMPORTER_RESOLVE_FORWARDED_EXPORTS` | uses `forwarded()` in `get()`. NOTE does not apply to `nt()` and `in()`.                |

## example output

```c
for ( i = *(_QWORD **)(*(_QWORD *)(__readgsqword(0x60u) + 24) + 16i64); ; i = (_QWORD *)*i )
  {
    v1 = i[6];
    v2 = *(unsigned int *)(*(signed int *)(v1 + 60) + v1 + 136);
    v3 = (_DWORD *)(v2 + v1);
    if ( v2 + v1 != v1 )
    {
      LODWORD(v4) = v3[6];
      if ( (_DWORD)v4 )
        break;
    }
LABEL_8:
    ;
  }
  while ( 1 )
  {
    v4 = (unsigned int)(v4 - 1);
    v5 = -2128831035;
    v6 = (char *)(v1 + *(unsigned int *)((unsigned int)v3[8] + 4 * v4 + v1));
    v7 = *v6;
    v8 = (signed __int64)(v6 + 1);
    if ( v7 )
    {
      do
      {
        ++v8;
        v5 = 16777619 * (v5 ^ v7);
        v7 = *(_BYTE *)(v8 - 1);
      }
      while ( v7 );
      if ( v5 == -973690651 )
        break;
    }
    if ( !(_DWORD)v4 )
      goto LABEL_8;
  }
  ((void (__fastcall *)(const char *))(v1
                                     + *(unsigned int *)(v1
                                                       + (unsigned int)v3[7]
                                                       + 4i64 * *(unsigned __int16 *)(v1 + (unsigned int)v3[9] + 2 * v4))))("hello world");
```
