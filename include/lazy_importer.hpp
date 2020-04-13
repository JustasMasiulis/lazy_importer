/*
 * Copyright 2018-2020 Justas Masiulis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// documentation is available at https://github.com/JustasMasiulis/lazy_importer

#ifndef LAZY_IMPORTER_HPP
#define LAZY_IMPORTER_HPP

#define LI_FN(name) \
    ::li::detail::lazy_function<::li::detail::khash(#name), decltype(&name)>()

#define LI_FN_DEF(name) ::li::detail::lazy_function<::li::detail::khash(#name), name>()

#define LI_MODULE(name) ::li::detail::lazy_module<::li::detail::khash(name)>()

// NOTE only std::forward is used from this header.
// If there is a need to eliminate this dependency the function itself is very small.
#include <utility>
#include <cstddef>
#include <intrin.h>

#ifndef LAZY_IMPORTER_NO_FORCEINLINE
#if defined(_MSC_VER)
#define LAZY_IMPORTER_FORCEINLINE __forceinline
#elif defined(__GNUC__) && __GNUC__ > 3
#define LAZY_IMPORTER_FORCEINLINE inline __attribute__((__always_inline__))
#else
#define LAZY_IMPORTER_FORCEINLINE inline
#endif
#else
#define LAZY_IMPORTER_FORCEINLINE inline
#endif

#ifdef LAZY_IMPORTER_CASE_INSENSITIVE
#define LAZY_IMPORTER_TOLOWER(c) (c >= 'A' && c <= 'Z' ? (c | (1 << 5)) : c)
#else
#define LAZY_IMPORTER_TOLOWER(c) (c)
#endif

namespace li { namespace detail {

    template<class First, class Second>
    struct pair {
        First  first;
        Second second;
    };

    namespace win {

        struct LIST_ENTRY_T {
            const char* Flink;
            const char* Blink;
        };

        struct UNICODE_STRING_T {
            unsigned short Length;
            unsigned short MaximumLength;
            wchar_t*       Buffer;
        };

        struct PEB_LDR_DATA_T {
            unsigned long Length;
            unsigned long Initialized;
            const char*   SsHandle;
            LIST_ENTRY_T  InLoadOrderModuleList;
        };

        struct PEB_T {
            unsigned char   Reserved1[2];
            unsigned char   BeingDebugged;
            unsigned char   Reserved2[1];
            const char*     Reserved3[2];
            PEB_LDR_DATA_T* Ldr;
        };

        struct LDR_DATA_TABLE_ENTRY_T {
            LIST_ENTRY_T InLoadOrderLinks;
            LIST_ENTRY_T InMemoryOrderLinks;
            LIST_ENTRY_T InInitializationOrderLinks;
            const char*  DllBase;
            const char*  EntryPoint;
            union {
                unsigned long SizeOfImage;
                const char*   _dummy;
            };
            UNICODE_STRING_T FullDllName;
            UNICODE_STRING_T BaseDllName;

            LAZY_IMPORTER_FORCEINLINE const LDR_DATA_TABLE_ENTRY_T*
                                            load_order_next() const noexcept
            {
                return reinterpret_cast<const LDR_DATA_TABLE_ENTRY_T*>(
                    InLoadOrderLinks.Flink);
            }
        };

        struct IMAGE_DOS_HEADER { // DOS .EXE header
            unsigned short e_magic; // Magic number
            unsigned short e_cblp; // Bytes on last page of file
            unsigned short e_cp; // Pages in file
            unsigned short e_crlc; // Relocations
            unsigned short e_cparhdr; // Size of header in paragraphs
            unsigned short e_minalloc; // Minimum extra paragraphs needed
            unsigned short e_maxalloc; // Maximum extra paragraphs needed
            unsigned short e_ss; // Initial (relative) SS value
            unsigned short e_sp; // Initial SP value
            unsigned short e_csum; // Checksum
            unsigned short e_ip; // Initial IP value
            unsigned short e_cs; // Initial (relative) CS value
            unsigned short e_lfarlc; // File address of relocation table
            unsigned short e_ovno; // Overlay number
            unsigned short e_res[4]; // Reserved words
            unsigned short e_oemid; // OEM identifier (for e_oeminfo)
            unsigned short e_oeminfo; // OEM information; e_oemid specific
            unsigned short e_res2[10]; // Reserved words
            long           e_lfanew; // File address of new exe header
        };

        struct IMAGE_FILE_HEADER {
            unsigned short Machine;
            unsigned short NumberOfSections;
            unsigned long  TimeDateStamp;
            unsigned long  PointerToSymbolTable;
            unsigned long  NumberOfSymbols;
            unsigned short SizeOfOptionalHeader;
            unsigned short Characteristics;
        };

        struct IMAGE_EXPORT_DIRECTORY {
            unsigned long  Characteristics;
            unsigned long  TimeDateStamp;
            unsigned short MajorVersion;
            unsigned short MinorVersion;
            unsigned long  Name;
            unsigned long  Base;
            unsigned long  NumberOfFunctions;
            unsigned long  NumberOfNames;
            unsigned long  AddressOfFunctions; // RVA from base of image
            unsigned long  AddressOfNames; // RVA from base of image
            unsigned long  AddressOfNameOrdinals; // RVA from base of image
        };

        struct IMAGE_DATA_DIRECTORY {
            unsigned long VirtualAddress;
            unsigned long Size;
        };

        struct IMAGE_OPTIONAL_HEADER64 {
            unsigned short       Magic;
            unsigned char        MajorLinkerVersion;
            unsigned char        MinorLinkerVersion;
            unsigned long        SizeOfCode;
            unsigned long        SizeOfInitializedData;
            unsigned long        SizeOfUninitializedData;
            unsigned long        AddressOfEntryPoint;
            unsigned long        BaseOfCode;
            unsigned long long   ImageBase;
            unsigned long        SectionAlignment;
            unsigned long        FileAlignment;
            unsigned short       MajorOperatingSystemVersion;
            unsigned short       MinorOperatingSystemVersion;
            unsigned short       MajorImageVersion;
            unsigned short       MinorImageVersion;
            unsigned short       MajorSubsystemVersion;
            unsigned short       MinorSubsystemVersion;
            unsigned long        Win32VersionValue;
            unsigned long        SizeOfImage;
            unsigned long        SizeOfHeaders;
            unsigned long        CheckSum;
            unsigned short       Subsystem;
            unsigned short       DllCharacteristics;
            unsigned long long   SizeOfStackReserve;
            unsigned long long   SizeOfStackCommit;
            unsigned long long   SizeOfHeapReserve;
            unsigned long long   SizeOfHeapCommit;
            unsigned long        LoaderFlags;
            unsigned long        NumberOfRvaAndSizes;
            IMAGE_DATA_DIRECTORY DataDirectory[16];
        };

        struct IMAGE_OPTIONAL_HEADER32 {
            unsigned short       Magic;
            unsigned char        MajorLinkerVersion;
            unsigned char        MinorLinkerVersion;
            unsigned long        SizeOfCode;
            unsigned long        SizeOfInitializedData;
            unsigned long        SizeOfUninitializedData;
            unsigned long        AddressOfEntryPoint;
            unsigned long        BaseOfCode;
            unsigned long        BaseOfData;
            unsigned long        ImageBase;
            unsigned long        SectionAlignment;
            unsigned long        FileAlignment;
            unsigned short       MajorOperatingSystemVersion;
            unsigned short       MinorOperatingSystemVersion;
            unsigned short       MajorImageVersion;
            unsigned short       MinorImageVersion;
            unsigned short       MajorSubsystemVersion;
            unsigned short       MinorSubsystemVersion;
            unsigned long        Win32VersionValue;
            unsigned long        SizeOfImage;
            unsigned long        SizeOfHeaders;
            unsigned long        CheckSum;
            unsigned short       Subsystem;
            unsigned short       DllCharacteristics;
            unsigned long        SizeOfStackReserve;
            unsigned long        SizeOfStackCommit;
            unsigned long        SizeOfHeapReserve;
            unsigned long        SizeOfHeapCommit;
            unsigned long        LoaderFlags;
            unsigned long        NumberOfRvaAndSizes;
            IMAGE_DATA_DIRECTORY DataDirectory[16];
        };

        struct IMAGE_NT_HEADERS {
            unsigned long     Signature;
            IMAGE_FILE_HEADER FileHeader;
#ifdef _WIN64
            IMAGE_OPTIONAL_HEADER64 OptionalHeader;
#else
            IMAGE_OPTIONAL_HEADER32 OptionalHeader;
#endif
        };

    } // namespace win

    // hashing stuff
    struct hash_t {
        using value_type                            = unsigned long;
        constexpr static value_type         offset  = 2166136261;
        constexpr static value_type         prime   = 16777619;
        constexpr static unsigned long long prime64 = prime;

        LAZY_IMPORTER_FORCEINLINE constexpr static value_type single(value_type value,
                                                                     char c) noexcept
        {
            return static_cast<hash_t::value_type>(
                (value ^ LAZY_IMPORTER_TOLOWER(c)) *
                static_cast<unsigned long long>(prime));
        }
    };

    template<class CharT = char>
    LAZY_IMPORTER_FORCEINLINE constexpr hash_t::value_type
    khash(const CharT* str, hash_t::value_type value = hash_t::offset) noexcept
    {
        return (*str ? khash(str + 1, hash_t::single(value, *str)) : value);
    }

    template<class CharT = char>
    LAZY_IMPORTER_FORCEINLINE hash_t::value_type hash(const CharT* str) noexcept
    {
        hash_t::value_type value = hash_t::offset;

        for(;;) {
            char c = *str++;
            if(!c)
                return value;
            value = hash_t::single(value, c);
        }
    }

    LAZY_IMPORTER_FORCEINLINE hash_t::value_type hash(
        const win::UNICODE_STRING_T& str) noexcept
    {
        auto       first = str.Buffer;
        const auto last  = first + (str.Length / sizeof(wchar_t));
        auto       value = hash_t::offset;
        for(; first != last; ++first)
            value = hash_t::single(value, static_cast<char>(*first));

        return value;
    }

    LAZY_IMPORTER_FORCEINLINE pair<hash_t::value_type, hash_t::value_type> hash_forwarded(
        const char* str) noexcept
    {
        pair<hash_t::value_type, hash_t::value_type> module_and_function{
            hash_t::offset, hash_t::offset
        };

        for(; *str != '.'; ++str)
            module_and_function.first = hash_t::single(module_and_function.first, *str);

        ++str;

        for(; *str; ++str)
            module_and_function.second = hash_t::single(module_and_function.second, *str);

        return module_and_function;
    }


    // some helper functions
    LAZY_IMPORTER_FORCEINLINE const win::PEB_T* peb() noexcept
    {
#if defined(_WIN64)
        return reinterpret_cast<const win::PEB_T*>(__readgsqword(0x60));
#elif defined(_WIN32)
        return reinterpret_cast<const win::PEB_T*>(__readfsdword(0x30));
#else
#error Unsupported platform. Open an issue and I'll probably add support.
#endif
    }

    LAZY_IMPORTER_FORCEINLINE const win::PEB_LDR_DATA_T* ldr()
    {
        return reinterpret_cast<const win::PEB_LDR_DATA_T*>(peb()->Ldr);
    }

    LAZY_IMPORTER_FORCEINLINE const win::IMAGE_NT_HEADERS* nt_headers(
        const char* base) noexcept
    {
        return reinterpret_cast<const win::IMAGE_NT_HEADERS*>(
            base + reinterpret_cast<const win::IMAGE_DOS_HEADER*>(base)->e_lfanew);
    }

    LAZY_IMPORTER_FORCEINLINE const win::IMAGE_EXPORT_DIRECTORY* image_export_dir(
        const char* base) noexcept
    {
        return reinterpret_cast<const win::IMAGE_EXPORT_DIRECTORY*>(
            base + nt_headers(base)->OptionalHeader.DataDirectory->VirtualAddress);
    }

    LAZY_IMPORTER_FORCEINLINE const win::LDR_DATA_TABLE_ENTRY_T* ldr_data_entry() noexcept
    {
        return reinterpret_cast<const win::LDR_DATA_TABLE_ENTRY_T*>(
            ldr()->InLoadOrderModuleList.Flink);
    }

    struct exports_directory {
        const char*                        _base;
        const win::IMAGE_EXPORT_DIRECTORY* _ied;
        unsigned long                      _ied_size;

    public:
        using size_type = unsigned long;

        LAZY_IMPORTER_FORCEINLINE
        exports_directory(const char* base) noexcept : _base(base)
        {
            const auto ied_data_dir = nt_headers(base)->OptionalHeader.DataDirectory[0];
            _ied = reinterpret_cast<const win::IMAGE_EXPORT_DIRECTORY*>(
                base + ied_data_dir.VirtualAddress);
            _ied_size = ied_data_dir.Size;
        }

        LAZY_IMPORTER_FORCEINLINE explicit operator bool() const noexcept
        {
            return reinterpret_cast<const char*>(_ied) != _base;
        }

        LAZY_IMPORTER_FORCEINLINE size_type size() const noexcept
        {
            return _ied->NumberOfNames;
        }

        LAZY_IMPORTER_FORCEINLINE const char* base() const noexcept { return _base; }
        LAZY_IMPORTER_FORCEINLINE const win::IMAGE_EXPORT_DIRECTORY* ied() const noexcept
        {
            return _ied;
        }

        LAZY_IMPORTER_FORCEINLINE const char* name(size_type index) const noexcept
        {
            return reinterpret_cast<const char*>(
                _base + reinterpret_cast<const unsigned long*>(
                            _base + _ied->AddressOfNames)[index]);
        }

        LAZY_IMPORTER_FORCEINLINE const char* address(size_type index) const noexcept
        {
            const auto* const rva_table =
                reinterpret_cast<const unsigned long*>(_base + _ied->AddressOfFunctions);

            const auto* const ord_table = reinterpret_cast<const unsigned short*>(
                _base + _ied->AddressOfNameOrdinals);

            return _base + rva_table[ord_table[index]];
        }

        LAZY_IMPORTER_FORCEINLINE bool is_forwarded(const char* export_address) const
            noexcept
        {
            const auto ui_ied = reinterpret_cast<const char*>(_ied);
            return (export_address > ui_ied && export_address < ui_ied + _ied_size);
        }
    };

    struct safe_module_enumerator {
        using value_type = const detail::win::LDR_DATA_TABLE_ENTRY_T;
        value_type*       value;
        value_type* const head;

        LAZY_IMPORTER_FORCEINLINE safe_module_enumerator() noexcept
            : value(ldr_data_entry()), head(value)
        {}

        LAZY_IMPORTER_FORCEINLINE void reset() noexcept { value = head; }

        LAZY_IMPORTER_FORCEINLINE bool next() noexcept
        {
            value = value->load_order_next();
            return value != head && value->DllBase;
        }
    };

    struct unsafe_module_enumerator {
        using value_type = const detail::win::LDR_DATA_TABLE_ENTRY_T*;
        value_type value;

        LAZY_IMPORTER_FORCEINLINE unsafe_module_enumerator() noexcept
            : value(ldr_data_entry())
        {}

        LAZY_IMPORTER_FORCEINLINE void reset() noexcept { value = ldr_data_entry(); }

        LAZY_IMPORTER_FORCEINLINE bool next() noexcept
        {
            value = value->load_order_next();
            return true;
        }
    };

    // provides the cached functions which use Derive classes methods
    template<class Derived, class DefaultType = void*>
    class lazy_base {
    protected:
        // This function is needed because every templated function
        // with different args has its own static buffer
        LAZY_IMPORTER_FORCEINLINE static void*& _cache() noexcept
        {
            static void* value = nullptr;
            return value;
        }

    public:
        template<class T = DefaultType>
        LAZY_IMPORTER_FORCEINLINE static T safe() noexcept
        {
            return Derived::template get<T, safe_module_enumerator>();
        }

        template<class T = DefaultType, class Enum = unsafe_module_enumerator>
        LAZY_IMPORTER_FORCEINLINE static T cached() noexcept
        {
            auto& cached = _cache();
            if(!cached)
                cached = Derived::template get<void*, Enum>();

            return (T)(cached);
        }

        template<class T = DefaultType>
        LAZY_IMPORTER_FORCEINLINE static T safe_cached() noexcept
        {
            return cached<T, safe_module_enumerator>();
        }
    };

    template<hash_t::value_type Hash>
    struct lazy_module : lazy_base<lazy_module<Hash>> {
        template<class T = void*, class Enum = unsafe_module_enumerator>
        LAZY_IMPORTER_FORCEINLINE static T get() noexcept
        {
            Enum e;
            do {
                if(hash(e.value->BaseDllName) == Hash)
                    return (T)(e.value->DllBase);
            } while(e.next());
            return {};
        }
    };

    template<hash_t::value_type Hash, class T>
    struct lazy_function : lazy_base<lazy_function<Hash, T>, T> {
        using base_type = lazy_base<lazy_function<Hash, T>, T>;

        template<class... Args>
        LAZY_IMPORTER_FORCEINLINE decltype(auto) operator()(Args&&... args) const
        {
#ifndef LAZY_IMPORTER_CACHE_OPERATOR_PARENS
            return get()(std::forward<Args>(args)...);
#else
            return this->cached()(std::forward<Args>(args)...);
#endif
        }

        template<class F = T, class Enum = unsafe_module_enumerator>
        LAZY_IMPORTER_FORCEINLINE static F get() noexcept
        {
            // for backwards compatability.
            // Before 2.0 it was only possible to resolve forwarded exports when
            // this macro was enabled
#ifdef LAZY_IMPORTER_RESOLVE_FORWARDED_EXPORTS
            return forwarded<F, Enum>();
#else
            Enum e;
            do {
                const exports_directory exports(e.value->DllBase);

                if(exports) {
                    auto export_index = exports.size();
                    while(export_index--)
                        if(hash(exports.name(export_index)) == Hash)
                            return (F)(exports.address(export_index));
                }
            } while(e.next());
            return {};
#endif
        }

        template<class F = T, class Enum = unsafe_module_enumerator>
        LAZY_IMPORTER_FORCEINLINE static F forwarded() noexcept
        {
            detail::win::UNICODE_STRING_T name;
            hash_t::value_type            module_hash   = 0;
            auto                          function_hash = Hash;

            Enum e;
            do {
                name = e.value->BaseDllName;
                name.Length -= 8; // get rid of .dll extension

                if(!module_hash || hash(name) == module_hash) {
                    const exports_directory exports(e.value->DllBase);

                    if(exports) {
                        auto export_index = exports.size();
                        while(export_index--)
                            if(hash(exports.name(export_index)) == function_hash) {
                                const auto addr = exports.address(export_index);

                                if(exports.is_forwarded(addr)) {
                                    auto hashes = hash_forwarded(
                                        reinterpret_cast<const char*>(addr));

                                    function_hash = hashes.second;
                                    module_hash   = hashes.first;

                                    e.reset();
                                    break;
                                }
                                return (F)(addr);
                            }
                    }
                }
            } while(e.next());
            return {};
        }

        template<class F = T>
        LAZY_IMPORTER_FORCEINLINE static F forwarded_safe() noexcept
        {
            return forwarded<F, safe_module_enumerator>();
        }

        template<class F = T, class Enum = unsafe_module_enumerator>
        LAZY_IMPORTER_FORCEINLINE static F forwarded_cached() noexcept
        {
            auto& value = base_type::_cache();
            if(!value)
                value = forwarded<void*, Enum>();
            return (F)(value);
        }

        template<class F = T>
        LAZY_IMPORTER_FORCEINLINE static F forwarded_safe_cached() noexcept
        {
            return forwarded_cached<F, safe_module_enumerator>();
        }

        template<class F = T, bool IsSafe = false, class Module>
        LAZY_IMPORTER_FORCEINLINE static F in(Module m) noexcept
        {
            if(IsSafe && !m)
                return {};

            const exports_directory exports((const char*)(m));
            if(IsSafe && !exports)
                return {};

            for(unsigned long i{};; ++i) {
                if(IsSafe && i == exports.size())
                    break;

                if(hash(exports.name(i)) == Hash)
                    return (F)(exports.address(i));
            }
            return {};
        }

        template<class F = T, class Module>
        LAZY_IMPORTER_FORCEINLINE static F in_safe(Module m) noexcept
        {
            return in<F, true>(m);
        }

        template<class F = T, bool IsSafe = false, class Module>
        LAZY_IMPORTER_FORCEINLINE static F in_cached(Module m) noexcept
        {
            auto& value = base_type::_cache();
            if(!value)
                value = in<void*, IsSafe>(m);
            return (F)(value);
        }

        template<class F = T, class Module>
        LAZY_IMPORTER_FORCEINLINE static F in_safe_cached(Module m) noexcept
        {
            return in_cached<F, true>(m);
        }

        template<class F = T>
        LAZY_IMPORTER_FORCEINLINE static F nt() noexcept
        {
            return in<F>(ldr_data_entry()->load_order_next()->DllBase);
        }

        template<class F = T>
        LAZY_IMPORTER_FORCEINLINE static F nt_safe() noexcept
        {
            return in_safe<F>(ldr_data_entry()->load_order_next()->DllBase);
        }

        template<class F = T>
        LAZY_IMPORTER_FORCEINLINE static F nt_cached() noexcept
        {
            return in_cached<F>(ldr_data_entry()->load_order_next()->DllBase);
        }

        template<class F = T>
        LAZY_IMPORTER_FORCEINLINE static F nt_safe_cached() noexcept
        {
            return in_safe_cached<F>(ldr_data_entry()->load_order_next()->DllBase);
        }
    };

}} // namespace li::detail

#endif // include guard
