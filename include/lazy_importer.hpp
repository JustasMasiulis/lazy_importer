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

// define LAZY_IMPORTER_WINDOWS_INCLUDE_DIR with your files include path
// not to use <Windows.h> and <Winternl.h>

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
        ::li::detail::find_nocache<::li::detail::hash(#name)>())
#define LI_FIND_DEF(name) \
    reinterpret_cast<name>(::li::detail::find_nocache<::li::detail::hash(#name)>())

// can be used for any function. Prefer for functions that you call often.
#define LI_FIND_CACHED(name)           \
    reinterpret_cast<decltype(&name)>( \
        ::li::detail::find_cached<::li::detail::hash(#name)>())
#define LI_FIND_DEF_CACHED(name) \
    reinterpret_cast<name>(::li::detail::find_cached<::li::detail::hash(#name)>())

// can be used for any function in provided module.
// There is no cached version because there might be functions with the same
// name in separate modules. If that is not a concern for you feel free to add
// it yourself
#define LI_GET(module_base, name)      \
    reinterpret_cast<decltype(&name)>( \
        ::li::detail::find_in_module<::li::detail::hash(#name)>(module_base))
#define LI_GET_DEF(module_base, name) \
    reinterpret_cast<name>(           \
        ::li::detail::find_in_module<::li::detail::hash(#name)>(module_base))

// can be used for ntdll exports. Prefer for functions that you call rarely.
#define LI_NT(name) \
    reinterpret_cast<decltype(&name)>(::li::detail::find_nt<::li::detail::hash(#name)>())
#define LI_NT_DEF(name) \
    reinterpret_cast<name>(::li::detail::find_nt<::li::detail::hash(#name)>())

// can be used for ntdll exports. Prefer for functions that you call often.
#define LI_NT_CACHED(name)             \
    reinterpret_cast<decltype(&name)>( \
        ::li::detail::find_nt_cached<::li::detail::hash(#name)>())
#define LI_NT_DEF_CACHED(name) \
    reinterpret_cast<name>(::li::detail::find_nt_cached<::li::detail::hash(#name)>())

#include <utility>
#include <cstdint>
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
#define LAZY_IMPORTER_INLINE inline
#endif

#ifdef LAZY_IMPORTER_CASE_INSENSITIVE
#define LAZY_IMPORTER_TOLOWER(c) (c >= 'A' && c <= 'Z' ? (c | (1 << 5)) : c)
#else
#define LAZY_IMPORTER_TOLOWER(c) (c)
#endif

namespace li { namespace detail {

    namespace win {

        struct LIST_ENTRY_T {
            std::uintptr_t Flink;
            std::uintptr_t Blink;
        };

        struct UNICODE_STRING_T {
            unsigned short Length;
            unsigned short MaximumLength;
            wchar_t*       Buffer;
        };

        struct PEB_LDR_DATA_T {
            unsigned long  Length;
            unsigned long  Initialized;
            std::uintptr_t SsHandle;
            LIST_ENTRY_T   InLoadOrderModuleList;
        };

        struct PEB_T {
            unsigned char   Reserved1[2];
            unsigned char   BeingDebugged;
            unsigned char   Reserved2[1];
            std::uintptr_t  Reserved3[2];
            PEB_LDR_DATA_T* Ldr;
        };

        struct LDR_DATA_TABLE_ENTRY_T {
            LIST_ENTRY_T   InLoadOrderLinks;
            LIST_ENTRY_T   InMemoryOrderLinks;
            LIST_ENTRY_T   InInitializationOrderLinks;
            std::uintptr_t DllBase;
            std::uintptr_t EntryPoint;
            union {
                unsigned long  SizeOfImage;
                std::uintptr_t _dummy;
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
            std::uint16_t e_magic; // Magic number
            std::uint16_t e_cblp; // Bytes on last page of file
            std::uint16_t e_cp; // Pages in file
            std::uint16_t e_crlc; // Relocations
            std::uint16_t e_cparhdr; // Size of header in paragraphs
            std::uint16_t e_minalloc; // Minimum extra paragraphs needed
            std::uint16_t e_maxalloc; // Maximum extra paragraphs needed
            std::uint16_t e_ss; // Initial (relative) SS value
            std::uint16_t e_sp; // Initial SP value
            std::uint16_t e_csum; // Checksum
            std::uint16_t e_ip; // Initial IP value
            std::uint16_t e_cs; // Initial (relative) CS value
            std::uint16_t e_lfarlc; // File address of relocation table
            std::uint16_t e_ovno; // Overlay number
            std::uint16_t e_res[4]; // Reserved words
            std::uint16_t e_oemid; // OEM identifier (for e_oeminfo)
            std::uint16_t e_oeminfo; // OEM information; e_oemid specific
            std::uint16_t e_res2[10]; // Reserved words
            long     e_lfanew; // File address of new exe header
        };

        struct IMAGE_FILE_HEADER {
            std::uint16_t      Machine;
            std::uint16_t      NumberOfSections;
            unsigned long TimeDateStamp;
            unsigned long PointerToSymbolTable;
            unsigned long NumberOfSymbols;
            std::uint16_t      SizeOfOptionalHeader;
            std::uint16_t      Characteristics;
        };

        struct IMAGE_EXPORT_DIRECTORY {
            unsigned long Characteristics;
            unsigned long TimeDateStamp;
            std::uint16_t      MajorVersion;
            std::uint16_t      MinorVersion;
            unsigned long Name;
            unsigned long Base;
            unsigned long NumberOfFunctions;
            unsigned long NumberOfNames;
            unsigned long AddressOfFunctions; // RVA from base of image
            unsigned long AddressOfNames; // RVA from base of image
            unsigned long AddressOfNameOrdinals; // RVA from base of image
        };

        struct IMAGE_DATA_DIRECTORY {
            unsigned long VirtualAddress;
            unsigned long Size;
        };

        struct IMAGE_OPTIONAL_HEADER64 {
            std::uint16_t             Magic;
            std::uint8_t              MajorLinkerVersion;
            std::uint8_t              MinorLinkerVersion;
            unsigned long        SizeOfCode;
            unsigned long        SizeOfInitializedData;
            unsigned long        SizeOfUninitializedData;
            unsigned long        AddressOfEntryPoint;
            unsigned long        BaseOfCode;
            std::uint64_t             ImageBase;
            unsigned long        SectionAlignment;
            unsigned long        FileAlignment;
            std::uint16_t             MajorOperatingSystemVersion;
            std::uint16_t             MinorOperatingSystemVersion;
            std::uint16_t             MajorImageVersion;
            std::uint16_t             MinorImageVersion;
            std::uint16_t             MajorSubsystemVersion;
            std::uint16_t             MinorSubsystemVersion;
            unsigned long        Win32VersionValue;
            unsigned long        SizeOfImage;
            unsigned long        SizeOfHeaders;
            unsigned long        CheckSum;
            std::uint16_t             Subsystem;
            std::uint16_t             DllCharacteristics;
            std::uint64_t             SizeOfStackReserve;
            std::uint64_t             SizeOfStackCommit;
            std::uint64_t             SizeOfHeapReserve;
            std::uint64_t             SizeOfHeapCommit;
            unsigned long        LoaderFlags;
            unsigned long        NumberOfRvaAndSizes;
            IMAGE_DATA_DIRECTORY DataDirectory[16];
        };

        struct IMAGE_OPTIONAL_HEADER32 {
            std::uint16_t             Magic;
            std::uint8_t              MajorLinkerVersion;
            std::uint8_t              MinorLinkerVersion;
            unsigned long        SizeOfCode;
            unsigned long        SizeOfInitializedData;
            unsigned long        SizeOfUninitializedData;
            unsigned long        AddressOfEntryPoint;
            unsigned long        BaseOfCode;
            unsigned long        BaseOfData;
            unsigned long        ImageBase;
            unsigned long        SectionAlignment;
            unsigned long        FileAlignment;
            std::uint16_t             MajorOperatingSystemVersion;
            std::uint16_t             MinorOperatingSystemVersion;
            std::uint16_t             MajorImageVersion;
            std::uint16_t             MinorImageVersion;
            std::uint16_t             MajorSubsystemVersion;
            std::uint16_t             MinorSubsystemVersion;
            unsigned long        Win32VersionValue;
            unsigned long        SizeOfImage;
            unsigned long        SizeOfHeaders;
            unsigned long        CheckSum;
            std::uint16_t             Subsystem;
            std::uint16_t             DllCharacteristics;
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
        using value_type                   = std::uint32_t;
        constexpr static value_type offset = 2166136261;
        constexpr static value_type prime  = 16777619;

        LAZY_IMPORTER_FORCEINLINE constexpr static void single(value_type& value,
                                                               char        c) noexcept
        {
            value = static_cast<hash_t::value_type>(
                (value ^ LAZY_IMPORTER_TOLOWER(c)) *
                static_cast<std::uint64_t>(hash_t::prime));
        }
    };

    template<class CharT = char>
    LAZY_IMPORTER_FORCEINLINE constexpr hash_t::value_type hash(const CharT* str) noexcept
    {
        // casts needed to get rid of warnings
        auto value = hash_t::offset;
        for(CharT c = *str; c; c = *++str)
            hash_t::single(value, c);

        return value;
    }

    LAZY_IMPORTER_FORCEINLINE hash_t::value_type
                              hash(const win::UNICODE_STRING_T& str) noexcept
    {
        auto       first = str.Buffer;
        const auto last  = first + ((str.Length / sizeof(wchar_t)) - 4); // - ".dll"
        auto       value = hash_t::offset;
        for(; first != last; ++first)
            hash_t::single(value, static_cast<char>(*first));

        return value;
    }

    LAZY_IMPORTER_FORCEINLINE std::pair<hash_t::value_type, hash_t::value_type>
                              hash_forwarded(const char* str) noexcept
    {
        std::pair<hash_t::value_type, hash_t::value_type> module_and_function{
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
                                    nt_headers(std::uintptr_t base) noexcept
    {
        return reinterpret_cast<const win::IMAGE_NT_HEADERS*>(
            base + reinterpret_cast<const win::IMAGE_DOS_HEADER*>(base)->e_lfanew);
    }

    LAZY_IMPORTER_FORCEINLINE const win::IMAGE_EXPORT_DIRECTORY*
                                    image_export_dir(std::uintptr_t base) noexcept
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
        std::uintptr_t                     _base;
        const win::IMAGE_EXPORT_DIRECTORY* _ied;
#ifdef LAZY_IMPORTER_RESOLVE_FORWARDED_EXPORTS
        unsigned long _ied_size;
#endif

    public:
        using size_type = unsigned long;

        LAZY_IMPORTER_FORCEINLINE
        exports_directory(std::uintptr_t base) noexcept : _base(base)
        {
#ifdef LAZY_IMPORTER_RESOLVE_FORWARDED_EXPORTS
            const auto ied_data_dir = nt_headers(base)->OptionalHeader.DataDirectory[0];
            _ied                    = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
                base + ied_data_dir.VirtualAddress);
            _ied_size = ied_data_dir.Size;
#else
            _ied = image_export_dir(base);
#endif
        }

        LAZY_IMPORTER_FORCEINLINE explicit operator bool() const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(_ied) != _base;
        }

        LAZY_IMPORTER_FORCEINLINE size_type size() const noexcept
        {
            return _ied->NumberOfNames;
        }

        LAZY_IMPORTER_FORCEINLINE std::uintptr_t base() const noexcept { return _base; }
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

        LAZY_IMPORTER_FORCEINLINE std::uintptr_t address(size_type index) const noexcept
        {
            const auto* const rva_table =
                reinterpret_cast<const unsigned long*>(_base + _ied->AddressOfFunctions);

            const auto* const ord_table = reinterpret_cast<const unsigned short*>(
                _base + _ied->AddressOfNameOrdinals);

            return _base + rva_table[ord_table[index]];
        }

#ifdef LAZY_IMPORTER_RESOLVE_FORWARDED_EXPORTS
        LAZY_IMPORTER_FORCEINLINE bool is_forwarded(std::uintptr_t export_address) const
            noexcept
        {
            const auto ui_ied = reinterpret_cast<std::uintptr_t>(_ied);
            return (export_address > ui_ied && export_address < ui_ied + _ied_size);
        }
#endif
    };

    template<hash_t::value_type Hash>
    LAZY_IMPORTER_FORCEINLINE std::uintptr_t
                              find_in_module(std::uintptr_t module_base) noexcept
    {
        const exports_directory exports(module_base);

        // we will trust the user with the fact that he provides valid module
        // which has the export
        for(unsigned long i = 0u;; ++i)
            if(hash(exports.name(i)) == Hash)
                return exports.address(i);
    }

    template<hash_t::value_type Hash>
    LAZY_IMPORTER_FORCEINLINE std::uintptr_t find_nt() noexcept
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
            return hash(module->BaseDllName) == _hash;
        }
    };

    template<hash_t::value_type Hash>
    LAZY_IMPORTER_FORCEINLINE std::uintptr_t find_nocache() noexcept
    {
        return find_nocache(Hash, allow_all_modules{});
    }

    template<class ModuleFilter = allow_all_modules>
    LAZY_IMPORTER_FORCEINLINE std::uintptr_t
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
    LAZY_IMPORTER_FORCEINLINE std::uintptr_t find_cached() noexcept
    {
        // don't replace this with "address = find_nocache<Hash>();"
        static std::uintptr_t address = 0;
        if(!address)
            kaddress = find_nocache<Hash>();
        return address;
    }

    template<hash_t::value_type Hash>
    LAZY_IMPORTER_FORCEINLINE std::uintptr_t find_nt_cached() noexcept
    {
        static std::uintptr_t address = 0;
        if(!address)
            address = find_nt<Hash>();
        return address;
    }
}} // namespace li::detail

#endif // include guard
