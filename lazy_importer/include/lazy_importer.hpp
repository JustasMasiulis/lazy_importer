#ifndef LAZY_IMPORTER_HPP
#define LAZY_IMPORTER_HPP

// in case you don't want to drag in the whole windows file
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

#define LI_GET(name)                   \
    reinterpret_cast<decltype(&name)>( \
        ::li::detail::find_nocache<::li::detail::hash(#name)>())

namespace li { namespace detail {

    namespace win {

        int __stdcall FreeLibrary(void*);
        void* __stdcall LoadLibraryA(const char*);

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

            const LDR_DATA_TABLE_ENTRY_T* load_order_next() const noexcept
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

    constexpr inline hash_value_type hash(const char* val) noexcept
    {
        // casts needed to get rid of warnings
        auto value = hash_offset;
        while (*val)
            value = static_cast<hash_value_type>(
                (value ^ *val++) * static_cast<std::uint64_t>(hash_prime));
        return value;
    }


    __forceinline const win::PEB_T* peb() noexcept
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

    __forceinline const IMAGE_NT_HEADERS*
    nt_headers(std::uintptr_t base) noexcept
    {
        return reinterpret_cast<const IMAGE_NT_HEADERS*>(
            base + reinterpret_cast<const IMAGE_DOS_HEADER*>(base)->e_lfanew);
    }

    __forceinline const IMAGE_EXPORT_DIRECTORY*
    image_export_dir(std::uintptr_t base) noexcept
    {
        return reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
            base +
            nt_headers(base)->OptionalHeader.DataDirectory->VirtualAddress);
    }

    const win::LDR_DATA_TABLE_ENTRY_T* ldr_data_entry()
    {
        return reinterpret_cast<const win::LDR_DATA_TABLE_ENTRY_T*>(
            peb()->Ldr->InLoadOrderModuleList.Flink);
    }

    struct exports_directory {
        std::uintptr_t                _base;
        const IMAGE_EXPORT_DIRECTORY* _ied;

    public:
        using size_type = unsigned long;

        exports_directory(std::uintptr_t base)
            : _base(base), _ied(image_export_dir(base))
        {}

        explicit operator bool() const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(_ied) != _base;
        }

        size_type size() const noexcept { return _ied->NumberOfNames; }

        const char* name(size_type index) const noexcept
        {
            return reinterpret_cast<const char*>(
                _base + reinterpret_cast<const unsigned long*>(
                            _base + _ied->AddressOfNames)[index]);
        }

        std::uintptr_t address(size_type index) const noexcept
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
    __forceinline std::uintptr_t find_nocache() noexcept
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

}} // namespace li::detail

#endif // include guard
