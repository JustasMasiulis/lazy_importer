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

// define LAZY_IMPORTER_CASE_INSENSITIVE to enable case insensitive comparisons

// define LAZY_IMPORTER_WINDOWS_INCLUDE_DIR with your files include path
// not to use <Windows.h> and <Winternl.h>

// usage example: LI_FIND(LoadLibraryA)("user32.dll");

// can be used for any function. Prefer for functions that you call rarely.
#define LI_FIND(name)                  \
    reinterpret_cast<decltype(&name)>( \
        ::li::detail::find_nocache<::li::detail::hash(#name)>())

// can be used for any function. Prefer for functions that you call often.
#define LI_FIND_CACHED(name)           \
    reinterpret_cast<decltype(&name)>( \
        ::li::detail::find_cached<::li::detail::hash(#name)>())

// can be used for any function in provided module.
// There is no cached version because there might be functions with the same
// name in separate modules. If that is not a concern for you feel free to add
// it yourself
#define LI_GET(module_base, name)      \
    reinterpret_cast<decltype(&name)>( \
        ::li::detail::find_in_module<::li::detail::hash(#name)>(module_base))

// can be used for ntdll exports. Prefer for functions that you call rarely.
#define LI_NT(name)                    \
    reinterpret_cast<decltype(&name)>( \
        ::li::detail::find_nt<::li::detail::hash(#name)>())

// can be used for ntdll exports. Prefer for functions that you call often.
#define LI_NT_CACHED(name)             \
    reinterpret_cast<decltype(&name)>( \
        ::li::detail::find_nt<::li::detail::hash(#name)>())

#ifndef LAZY_IMPORTER_WINDOWS_INCLUDE_DIR
#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <Windows.h>
#include <Winternl.h>
#undef WIN32_LEAN_AND_MEAN
#undef WIN32_NO_STATUS
#else
#include LAZY_IMPORTER_WINDOWS_INCLUDE_DIR
#endif

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

        struct PEB_LDR_DATA_T {
            unsigned long  Length;
            unsigned long  Initialized;
            std::uintptr_t SsHandle;
            LIST_ENTRY     InLoadOrderModuleList;
        };

        struct LDR_DATA_TABLE_ENTRY_T {
            LIST_ENTRY     InLoadOrderLinks;
            LIST_ENTRY     InMemoryOrderLinks;
            LIST_ENTRY     InInitializationOrderLinks;
            std::uintptr_t DllBase;
            std::uintptr_t EntryPoint;
            union {
                unsigned long  SizeOfImage;
                std::uintptr_t _dummy;
            };
            UNICODE_STRING FullDllName;
            UNICODE_STRING BaseDllName;

            LAZY_IMPORTER_FORCEINLINE const LDR_DATA_TABLE_ENTRY_T*
                                            load_order_next() const noexcept
            {
                return reinterpret_cast<const LDR_DATA_TABLE_ENTRY_T*>(
                    InLoadOrderLinks.Flink);
            }
        };

        struct PEB_T {
            unsigned char   Reserved1[2];
            unsigned char   BeingDebugged;
            unsigned char   Reserved2[1];
            std::uintptr_t  Reserved3[2];
            PEB_LDR_DATA_T* Ldr;
        };

        struct TEB_T {
            void*   Reserved1[12];
            PEB_T*  ProcessEnvironmentBlock;
            void*   Reserved2[399];
            uint8_t Reserved3[1952];
            void*   TlsSlots[64];
            uint8_t Reserved4[8];
            void*   Reserved5[26];
            void*   ReservedForOle; // Windows 2000 only
            void*   Reserved6[4];
            void*   TlsExpansionSlots;
        };

    } // namespace win

    // hashing stuff
    using hash_value_type                        = std::uint32_t;
    constexpr static hash_value_type hash_offset = 2166136261;
    constexpr static hash_value_type hash_prime  = 16777619;

    LAZY_IMPORTER_FORCEINLINE constexpr hash_value_type
    hash(const char* str) noexcept
    {
        // casts needed to get rid of warnings
        auto value = hash_offset;
        for (char c = *str; c; c = *++str)
            value = static_cast<hash_value_type>(
                (value ^ LAZY_IMPORTER_TOLOWER(c)) *
                static_cast<std::uint64_t>(hash_prime));

        return value;
    }


    LAZY_IMPORTER_FORCEINLINE const win::PEB_T* peb() noexcept
    {
#if defined(_WIN64)
        return reinterpret_cast<const win::TEB_T*>(
                   __readgsqword(offsetof(NT_TIB, Self)))
            ->ProcessEnvironmentBlock;
#else
        return reinterpret_cast<const win::TEB_T*>(
                   __readfsdword(offsetof(NT_TIB, Self)))
            ->ProcessEnvironmentBlock;
#endif
    }

    LAZY_IMPORTER_FORCEINLINE const IMAGE_NT_HEADERS*
                                    nt_headers(std::uintptr_t base) noexcept
    {
        return reinterpret_cast<const IMAGE_NT_HEADERS*>(
            base + reinterpret_cast<const IMAGE_DOS_HEADER*>(base)->e_lfanew);
    }

    LAZY_IMPORTER_FORCEINLINE const IMAGE_EXPORT_DIRECTORY*
                                    image_export_dir(std::uintptr_t base) noexcept
    {
        return reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
            base +
            nt_headers(base)->OptionalHeader.DataDirectory->VirtualAddress);
    }

    LAZY_IMPORTER_FORCEINLINE const win::LDR_DATA_TABLE_ENTRY_T*
                                    ldr_data_entry() noexcept
    {
        return reinterpret_cast<const win::LDR_DATA_TABLE_ENTRY_T*>(
            peb()->Ldr->InLoadOrderModuleList.Flink);
    }

    struct exports_directory {
        std::uintptr_t                _base;
        const IMAGE_EXPORT_DIRECTORY* _ied;

    public:
        using size_type = unsigned long;

        LAZY_IMPORTER_FORCEINLINE
        exports_directory(std::uintptr_t base) noexcept
            : _base(base), _ied(image_export_dir(base))
        {}

        LAZY_IMPORTER_FORCEINLINE explicit operator bool() const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(_ied) != _base;
        }

        LAZY_IMPORTER_FORCEINLINE size_type size() const noexcept
        {
            return _ied->NumberOfNames;
        }

        LAZY_IMPORTER_FORCEINLINE const char* name(size_type index) const
            noexcept
        {
            return reinterpret_cast<const char*>(
                _base + reinterpret_cast<const unsigned long*>(
                            _base + _ied->AddressOfNames)[index]);
        }

        LAZY_IMPORTER_FORCEINLINE std::uintptr_t address(size_type index) const
            noexcept
        {
            const auto* const rva_table =
                reinterpret_cast<const unsigned long*>(
                    _base + _ied->AddressOfFunctions);

            const auto* const ord_table =
                reinterpret_cast<const unsigned short*>(
                    _base + _ied->AddressOfNameOrdinals);

            return _base + rva_table[ord_table[index]];
        }
    };

    template<std::uint32_t Hash>
    LAZY_IMPORTER_FORCEINLINE std::uintptr_t
                              find_in_module(std::uintptr_t module_base) noexcept
    {
        const exports_directory exports(module_base);

        // we will trust the user with the fact that he provides valid module
        // which has the export
        for (auto i = 0u;; ++i)
            if (hash(exports.name(i)) == Hash)
                return exports.address(i);
    }

    template<std::uint32_t Hash>
    LAZY_IMPORTER_FORCEINLINE std::uintptr_t find_nt() noexcept
    {
        // load the next entry which will be ntdll
        const auto* const head = ldr_data_entry()->load_order_next();
        return find_in_module<Hash>(head->DllBase);
    }

    template<std::uint32_t Hash>
    LAZY_IMPORTER_FORCEINLINE std::uintptr_t find_nocache() noexcept
    {
        const auto* head = ldr_data_entry();

        while (true) {
            const exports_directory exports(head->DllBase);

            if (exports)
                for (auto i = 0u; i < exports.size(); ++i)
                    if (hash(exports.name(i)) == Hash)
                        return exports.address(i);

            head = head->load_order_next();
        }
    }

    template<std::uint32_t Hash>
    LAZY_IMPORTER_FORCEINLINE std::uintptr_t find_cached() noexcept
    {
        static std::uintptr_t address = 0;
        if (!address)
            address = find_nocache<Hash>();
        return address;
    }

    template<std::uint32_t Hash>
    LAZY_IMPORTER_FORCEINLINE std::uintptr_t find_nt_cached() noexcept
    {
        static std::uintptr_t address = 0;
        if (!address)
            address = find_nt<Hash>();
        return address;
    }

}} // namespace li::detail

#endif // include guard
