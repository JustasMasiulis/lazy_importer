/*
 * Copyright 2018 Justas Masiulis
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

#ifndef LAZY_IMPORTER_HPP
#define LAZY_IMPORTER_HPP

// define LAZY_IMPORTER_NO_FORCEINLINE to disable force inlining

// define LAZY_IMPORTER_RESOLVE_FORWARDED_EXPORTS to enable resolution of forwarded
// exports. IMPORTANT: LAZY_IMPORTER_CASE_INSENSITIVE might be necessary for this option
// to function properly.

// define LAZY_IMPORTER_CASE_INSENSITIVE to enable case insensitive comparisons


// DEF functions are for use with typedefs
// non DEF functions are for use with function pointers


// usage examples:

// using a function pointer:
// HMODULE __stdcall LoadLibraryA(const char*);
// LI_FIND(LoadLibraryA)("user32.dll");

// using a typedef:
// using LoadLibraryA = HMODULE (__stdcall*)(const char*);
// LI_FIND_DEF(LoadLibraryA)("user32.dll");

// can be used for any function. Prefer for functions that you call rarely.
#define LI_FIND(name)                  \
    reinterpret_cast<decltype(&name)>( \
        ::li::detail::find_nocache<::li::detail::khash(#name)>())
#define LI_FIND_DEF(name) \
    reinterpret_cast<name>(::li::detail::find_nocache<::li::detail::khash(#name)>())

// can be used for any function. Prefer for functions that you call often.
#define LI_FIND_CACHED(name)           \
    reinterpret_cast<decltype(&name)>( \
        ::li::detail::find_cached<::li::detail::khash(#name)>())
#define LI_FIND_DEF_CACHED(name) \
    reinterpret_cast<name>(::li::detail::find_cached<::li::detail::khash(#name)>())

// can be used for any function in provided module.
// There is no cached version because there might be functions with the same
// name in separate modules. If that is not a concern for you feel free to add
// it yourself
#define LI_GET(module_base, name)      \
    reinterpret_cast<decltype(&name)>( \
        ::li::detail::find_in_module<::li::detail::khash(#name)>(module_base))
#define LI_GET_DEF(module_base, name) \
    reinterpret_cast<name>(           \
        ::li::detail::find_in_module<::li::detail::khash(#name)>(module_base))

// can be used for ntdll exports. Prefer for functions that you call rarely.
#define LI_NT(name) \
    reinterpret_cast<decltype(&name)>(::li::detail::find_nt<::li::detail::khash(#name)>())
#define LI_NT_DEF(name) \
    reinterpret_cast<name>(::li::detail::find_nt<::li::detail::khash(#name)>())

// can be used for ntdll exports. Prefer for functions that you call often.
#define LI_NT_CACHED(name)             \
    reinterpret_cast<decltype(&name)>( \
        ::li::detail::find_nt_cached<::li::detail::khash(#name)>())
#define LI_NT_DEF_CACHED(name) \
    reinterpret_cast<name>(::li::detail::find_nt_cached<::li::detail::khash(#name)>())

// returns dll base address or an infinite loop or crashes if it does not exist
#define LI_MODULE(name) ::li::detail::module_handle<::li::detail::khash(name)>()

// returns dll base address or nullptr if it does not exist
#define LI_MODULE_SAFE(name) ::li::detail::module_handle_safe<::li::detail::khash(name)>()

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

        struct NT_TIB {
            void*   ExceptionList;
            void*   StackBase;
            void*   StackLimit;
            void*   SubSystemTib;
            void*   FiberData;
            void*   ArbitraryUserPointer;
            NT_TIB* Self;
        };

        struct TEB {
            void*  Reserved1[12];
            PEB_T* ProcessEnvironmentBlock;
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
                break;
            value = hash_t::single(value, c);
        }
        return value;
    }

    LAZY_IMPORTER_FORCEINLINE hash_t::value_type
                              hash(const win::UNICODE_STRING_T& str) noexcept
    {
        auto       first = str.Buffer;
        const auto last  = first + (str.Length / sizeof(wchar_t));
        auto       value = hash_t::offset;
        for(; first != last; ++first)
            value = hash_t::single(value, static_cast<char>(*first));

        return value;
    }

    LAZY_IMPORTER_FORCEINLINE pair<hash_t::value_type, hash_t::value_type>
                              hash_forwarded(const char* str) noexcept
    {
        pair<hash_t::value_type, hash_t::value_type> module_and_function{
            hash_t::offset, hash_t::offset
        };

        for(; *str != '.'; ++str)
            hash_t::single(module_and_function.first, *str);

        ++str;

        for(; *str; ++str)
            hash_t::single(module_and_function.second, *str);

        return module_and_function;
    }


    // some helper functions
    LAZY_IMPORTER_FORCEINLINE const win::PEB_T* peb() noexcept
    {
#if defined(_WIN64)
        return reinterpret_cast<const win::TEB*>(
                   __readgsqword(offsetof(win::NT_TIB, Self)))
            ->ProcessEnvironmentBlock;
#elif defined(_WIN32)
        return reinterpret_cast<const win::TEB*>(
                   __readfsdword(offsetof(win::NT_TIB, Self)))
            ->ProcessEnvironmentBlock;
#else
#error unsupported platform. Open an issues and I might add something for you.
#endif
    }

    LAZY_IMPORTER_FORCEINLINE const win::PEB_LDR_DATA_T* ldr()
    {
        return reinterpret_cast<const win::PEB_LDR_DATA_T*>(peb()->Ldr);
    }

    LAZY_IMPORTER_FORCEINLINE const win::IMAGE_NT_HEADERS*
                                    nt_headers(const char* base) noexcept
    {
        return reinterpret_cast<const win::IMAGE_NT_HEADERS*>(
            base + reinterpret_cast<const win::IMAGE_DOS_HEADER*>(base)->e_lfanew);
    }

    LAZY_IMPORTER_FORCEINLINE const win::IMAGE_EXPORT_DIRECTORY*
                                    image_export_dir(const char* base) noexcept
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
#ifdef LAZY_IMPORTER_RESOLVE_FORWARDED_EXPORTS
        unsigned long _ied_size;
#endif

    public:
        using size_type = unsigned long;

        LAZY_IMPORTER_FORCEINLINE
        exports_directory(const char* base) noexcept : _base(base)
        {
#ifdef LAZY_IMPORTER_RESOLVE_FORWARDED_EXPORTS
            const auto ied_data_dir = nt_headers(base)->OptionalHeader.DataDirectory[0];
            _ied = reinterpret_cast<const win::IMAGE_EXPORT_DIRECTORY*>(
                base + ied_data_dir.VirtualAddress);
            _ied_size = ied_data_dir.Size;
#else
            _ied = image_export_dir(base);
#endif
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

#ifdef LAZY_IMPORTER_RESOLVE_FORWARDED_EXPORTS
        LAZY_IMPORTER_FORCEINLINE bool is_forwarded(const char* export_address) const
            noexcept
        {
            const auto ui_ied = reinterpret_cast<const char*>(_ied);
            return (export_address > ui_ied && export_address < ui_ied + _ied_size);
        }
#endif
    };

    template<hash_t::value_type Hash>
    LAZY_IMPORTER_FORCEINLINE const char* module_handle()
    {
        auto head = ldr_data_entry();
        while(true) {
            if(hash(head->BaseDllName) == Hash)
                return head->DllBase;
            head = head->load_order_next();
        }
    }

    template<hash_t::value_type Hash>
    LAZY_IMPORTER_FORCEINLINE const char* module_handle_safe()
    {
        const auto head = ldr_data_entry();
        auto       it   = head;
        while(true) {
            if(hash(it->BaseDllName) == Hash)
                return it->DllBase;

            if(it->InLoadOrderLinks.Flink == reinterpret_cast<const char*>(head))
                return 0;

            it = it->load_order_next();
        }
    }

    template<hash_t::value_type Hash>
    LAZY_IMPORTER_FORCEINLINE const char* find_in_module(const char* module_base) noexcept
    {
        const exports_directory exports(module_base);

        // we will trust the user with the fact that he provides valid module
        // which has the export
        for(unsigned long i = 0u;; ++i)
            if(hash(exports.name(i)) == Hash)
                return exports.address(i);
    }

    template<hash_t::value_type Hash>
    LAZY_IMPORTER_FORCEINLINE const char* find_nt() noexcept
    {
        // load the next entry which will be ntdll
        const auto* const head = ldr_data_entry()->load_order_next();
        return find_in_module<Hash>(head->DllBase);
    }

    struct allow_all_modules {
        LAZY_IMPORTER_FORCEINLINE constexpr bool
        operator()(const win::LDR_DATA_TABLE_ENTRY_T*) const noexcept
        {
            return true;
        }
    };

    struct modules_by_hash {
        hash_t::value_type _hash;

        LAZY_IMPORTER_FORCEINLINE bool
        operator()(const win::LDR_DATA_TABLE_ENTRY_T* module) const noexcept
        {
            auto name = module->BaseDllName;
            name.Length -= 8; // .dll
            return hash(name) == _hash;
        }
    };

    template<hash_t::value_type Hash>
    LAZY_IMPORTER_FORCEINLINE const char* find_nocache() noexcept
    {
        return find_nocache(Hash, allow_all_modules{});
    }

    template<class ModuleFilter = allow_all_modules>
    LAZY_IMPORTER_FORCEINLINE const char*
    find_nocache(hash_t::value_type function_hash, ModuleFilter module_filter) noexcept
    {
        const auto* head = ldr_data_entry();

        while(true) {
            if(module_filter(head)) {
                const exports_directory exports(head->DllBase);

                if(exports)
                    for(auto i = 0u; i < exports.size(); ++i)
                        if(hash(exports.name(i)) == function_hash) {
                            const auto addr = exports.address(i);

#ifdef LAZY_IMPORTER_RESOLVE_FORWARDED_EXPORTS
                            if(exports.is_forwarded(addr)) {
                                auto hashes =
                                    hash_forwarded(reinterpret_cast<const char*>(addr));
                                return find_nocache(hashes.second,
                                                    modules_by_hash{ hashes.first });
                            }
#endif
                            return addr;
                        }
            }

            head = head->load_order_next();
        }
    }

    template<hash_t::value_type Hash>
    LAZY_IMPORTER_FORCEINLINE const char* find_cached() noexcept
    {
        // don't replace this with "address = find_nocache<Hash>();"
        static const char* address = 0;
        if(!address)
            address = find_nocache<Hash>();
        return address;
    }

    template<hash_t::value_type Hash>
    LAZY_IMPORTER_FORCEINLINE const char* find_nt_cached() noexcept
    {
        static const char* address = 0;
        if(!address)
            address = find_nt<Hash>();
        return address;
    }
}} // namespace li::detail

#endif // include guard
