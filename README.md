# lazy importer [![](https://img.shields.io/badge/version-2.1.0-green.svg)]()

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
- Hashes are randomized for each compilation to defeat basic hash database attacks.

## documentation

- `LI_FN(function_pointer)  -> lazy_function`
- `LI_FN_DEF(function_type) -> lazy_function`
- `LI_MODULE(module_name)  -> lazy_module`

---

- `safe` indicates that when function cannot complete its task successfully 0 is returned instead of undefined behaviour manifesting.
- `cached` indicates that the result is only computed during the first call and later reused.
- `forwarded` indicates that export forwarding will be correctly resolved.

#### **`lazy_module`**

<table>
  <tr>
    <th>function</th>
    <th>safe</th>
    <th>cached</th>
  </tr>
  <tr>
    <td colspan="4">Attempts to find the given module and returns its address</td>
  </tr>
  <tr>
    <td><code>get&lt;T = void*&gt;() -&gt; T</code></td>
    <td align="center">:x:</td>
    <td align="center">:x:</td>
  </tr>
    <tr>
    <td><code>safe&lt;T = void*&gt;() -&gt; T</code></td>
    <td align="center">:white_check_mark:</td>
    <td align="center">:x:</td>
  </tr>
  <tr>
    <td><code>cached&lt;T = void*&gt;() -&gt; T</code></td>
    <td align="center">:x:</td>
    <td align="center">:white_check_mark:</td>
  </tr>
  <tr>
    <td><code>safe_cached&lt;T = void*&gt;() -&gt; T</code></td>
    <td align="center">:white_check_mark:</td>
    <td align="center">:white_check_mark:</td>
  </tr>
  <tr>
    <td colspan="4">Attemps to find the given module using the given LDR_DATA_TABLE_ENTRY pointer</td>
  </tr>
  <tr>
    <td><code>in&lt;T = void*, Ldr&gt;(Ldr ldr_entry) -&gt; T</code></td>
    <td align="center">:white_check_mark:</td>
    <td align="center">:x:</td>
  </tr>
  <tr>
    <td><code>in_cached&lt;T = void*, Ldr&gt;(Ldr ldr_entry) -&gt; T</code></td>
    <td align="center">:white_check_mark:</td>
    <td align="center">:white_check_mark:</td>
  </tr>
</table>

#### **`lazy_function<F>`**

<table>
  <tr>
    <th>function</th>
    <th>safe</th>
    <th>cached</th>
    <th>forwarded</th>
  </tr>
  <tr>
    <td colspan="4">calls resolved export using given arguments</td>
  </tr>
  <tr>
    <td><code>operator()(...) -&gt; result_of&lt;F, ...&gt;</code></td>
    <td align="center">:x:</td>
    <td align="center">:x:</td>
    <td align="center">:x:</td>
  </tr>
  <tr>
    <td colspan="4">attempts to resolve an export in all loaded modules and returns the function address</td>
  </tr>
  <tr>
    <td><code>get&lt;T = F&gt;() -&gt; T</code></td>
    <td align="center">:x:</td>
    <td align="center">:x:</td>
    <td align="center">:x:</td>
  </tr>
  <tr>
    <td><code>safe&lt;T = F&gt;() -&gt; T</code></td>
    <td align="center">:white_check_mark:</td>
    <td align="center">:x:</td>
    <td align="center">:x:</td>
  </tr>
  <tr>
    <td><code>cached&lt;T = F&gt;() -&gt; T</code></td>
    <td align="center">:x:</td>
    <td align="center">:white_check_mark:</td>
    <td align="center">:x:</td>
  </tr>
  <tr>
    <td><code>safe_cached&lt;T = F&gt;() -&gt; T</code></td>
    <td align="center">:white_check_mark:</td>
    <td align="center">:white_check_mark:</td>
    <td align="center">:x:</td>
  </tr>
  <tr>
    <td><code>forwarded&lt;T = F&gt;() -&gt; T</code></td>
    <td align="center">:x:</td>
    <td align="center">:x:</td>
    <td align="center">:white_check_mark:</td>
  </tr>
  <tr>
    <td><code>forwarded_safe&lt;T = F&gt;() -&gt; T</code></td>
    <td align="center">:white_check_mark:</td>
    <td align="center">:x:</td>
    <td align="center">:white_check_mark:</td>
  </tr>
  <tr>
    <td><code>forwarded_cached&lt;T = F&gt;() -&gt; T</code></td>
    <td align="center">:x:</td>
    <td align="center">:white_check_mark:</td>
    <td align="center">:white_check_mark:</td>
  </tr>
  <tr>
    <td><code>forwarded_safe_cached&lt;T = F&gt;() -&gt; T</code></td>
    <td align="center">:white_check_mark:</td>
    <td align="center">:white_check_mark:</td>
    <td align="center">:white_check_mark:</td>
  </tr>
  <tr>
    <td colspan="4">attempts to resolve an export in the given module and returns the function address</td>
  </tr>
  <tr>
    <td><code>in&lt;T = F, A&gt;(A module_address) -&gt; T</code></td>
    <td align="center">:x:</td>
    <td align="center">:x:</td>
    <td align="center">:x:</td>
  </tr>
  <tr>
    <td><code>in_safe&lt;T = F, A&gt;(A module_address) -&gt; T</code></td>
    <td align="center">:white_check_mark:</td>
    <td align="center">:x:</td>
    <td align="center">:x:</td>
  </tr>
  <tr>
    <td><code>in_cached&lt;T = F, A&gt;(A module_address) -&gt; T</code></td>
    <td align="center">:x:</td>
    <td align="center">:white_check_mark:</td>
    <td align="center">:x:</td>
  </tr>
  <tr>
    <td><code>in_safe_cached&lt;T = F, A&gt;(A module_address) -&gt; T</code></td>
    <td align="center">:white_check_mark:</td>
    <td align="center">:white_check_mark:</td>
    <td align="center">:x:</td>
  </tr>
  <tr>
    <td colspan="4">attempts to resolve an export in <code>ntdll</code> and returns the function address</td>
  </tr>
  <tr>
    <td><code>nt&lt;T = F&gt;() -&gt; T</code></td>
    <td align="center">:x:</td>
    <td align="center">:x:</td>
    <td align="center">:x:</td>
  </tr>
  <tr>
    <td><code>nt_safe&lt;T = F&gt;() -&gt; T</code></td>
    <td align="center">:white_check_mark:</td>
    <td align="center">:x:</td>
    <td align="center">:x:</td>
  </tr>
  <tr>
    <td><code>nt_cached&lt;T = F&gt;() -&gt; T</code></td>
    <td align="center">:x:</td>
    <td align="center">:white_check_mark:</td>
    <td align="center">:x:</td>
  </tr>
  <tr>
    <td><code>nt_safe_cached&lt;T = F&gt;() -&gt; T</code></td>
    <td align="center">:white_check_mark:</td>
    <td align="center">:white_check_mark:</td>
    <td align="center">:x:</td>
  </tr>
</table>

#### extra configuration

| `#define`                                 | effects                                                                                 |
| ----------------------------------------- | --------------------------------------------------------------------------------------- |
| `LAZY_IMPORTER_NO_FORCEINLINE`            | disables force inlining                                                                 |
| `LAZY_IMPORTER_CASE_INSENSITIVE`          | enables case insensitive comparison. Might be required for forwarded export resolution. |
| `LAZY_IMPORTER_CACHE_OPERATOR_PARENS`     | uses `cached()` instead of `get()` in `operator()` of lazy_function                     |
| `LAZY_IMPORTER_RESOLVE_FORWARDED_EXPORTS` | uses `forwarded()` in `get()`. WARNING does not apply to `nt()` and `in()`.             |
| `LAZY_IMPORTER_HARDENED_MODULE_CHECKS`    | adds extra sanity checks to module enumeration.                                         |
| `LAZY_IMPORTER_NO_CPP_FORWARD`            | Removes dependence on `<utility>` c++ header.                                           | 

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

## People that have supported this project
I would like to thank people that have reached out to me and donated some money to support me and my projects

* [@DefCon42](https://github.com/DefCon42)
* [@Mecanik](https://github.com/Mecanik)
