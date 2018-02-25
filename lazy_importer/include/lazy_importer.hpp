#ifndef LAZY_IMPORTER_HPP
#define LAZY_IMPORTER_HPP

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <intrin.h>

#define LI_GET(name)                   \
    reinterpret_cast<decltype(&name)>( \
        ::li::detail::find_nocache<::li::detail::c_hash(#name)>())
#define LI_LOAD(name)                                                            \
    reinterpret_cast<std::uintptr_t>(                                            \
        reinterpret_cast<decltype(&::li::detail::win::LoadLibraryA)>(            \
            ::li::detail::find_nocache<::li::detail::c_hash("LoadLibraryA")>())( \
            name))

#define LI_UNLOAD(handle)                                        \
    reinterpret_cast<decltype(&::li::detail::win::FreeLibrary)>( \
        ::li::detail::find_cached<::li::detail::c_hash("FreeLibrary")>())(handle)


namespace li { namespace detail {

    constexpr static std::uint32_t hash_offset = 2166136261;
    constexpr static std::uint32_t hash_prime  = 16777619;

    template<std::size_t N>
    inline constexpr std::uint32_t c_hash(const char (&val)[N]) noexcept
    {
        auto hash = detail::hash_offset;
        for (std::size_t i = 0; i < N - 1; ++i)
            hash = static_cast<std::uint32_t>(
                (hash ^ val[i]) * static_cast<std::uint64_t>(detail::hash_prime));

        return hash;
    }

    struct hash final {
        using argument_type = const char*;
        using result_type   = std::uint32_t;

        inline result_type operator()(const char* val) const noexcept
        {
            result_type hash = hash_offset;
            while (*val)
                hash = (hash ^ *val++) * hash_prime;
            return hash;
        }
    };

    namespace win {

        int __stdcall FreeLibrary(void*);
        void* __stdcall LoadLibraryA(const char*);
        void __stdcall ExitProcess(unsigned int);

        constexpr static auto num_dir_entries  = 16;
        constexpr static auto dir_entry_export = 0;

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
        };

        struct PEB_T {
            unsigned char   Reserved1[2];
            unsigned char   BeingDebugged;
            unsigned char   Reserved2[1];
            std::uintptr_t  Reserved3[2];
            PEB_LDR_DATA_T* Ldr;
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

        struct IMAGE_DOS_HEADER { // DOS .EXE header
            uint16_t e_magic; // Magic number
            uint16_t e_cblp; // Bytes on last page of file
            uint16_t e_cp; // Pages in file
            uint16_t e_crlc; // Relocations
            uint16_t e_cparhdr; // Size of header in paragraphs
            uint16_t e_minalloc; // Minimum extra paragraphs needed
            uint16_t e_maxalloc; // Maximum extra paragraphs needed
            uint16_t e_ss; // Initial (relative) SS value
            uint16_t e_sp; // Initial SP value
            uint16_t e_csum; // Checksum
            uint16_t e_ip; // Initial IP value
            uint16_t e_cs; // Initial (relative) CS value
            uint16_t e_lfarlc; // File address of relocation table
            uint16_t e_ovno; // Overlay number
            uint16_t e_res[4]; // Reserved words
            uint16_t e_oemid; // OEM identifier (for e_oeminfo)
            uint16_t e_oeminfo; // OEM information; e_oemid specific
            uint16_t e_res2[10]; // Reserved words
            long     e_lfanew; // File address of new exe header
        };

        struct IMAGE_FILE_HEADER {
            uint16_t      Machine;
            uint16_t      NumberOfSections;
            unsigned long TimeDateStamp;
            unsigned long PointerToSymbolTable;
            unsigned long NumberOfSymbols;
            uint16_t      SizeOfOptionalHeader;
            uint16_t      Characteristics;
        };

        struct IMAGE_EXPORT_DIRECTORY {
            unsigned long Characteristics;
            unsigned long TimeDateStamp;
            uint16_t      MajorVersion;
            uint16_t      MinorVersion;
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
            uint16_t             Magic;
            uint8_t              MajorLinkerVersion;
            uint8_t              MinorLinkerVersion;
            unsigned long        SizeOfCode;
            unsigned long        SizeOfInitializedData;
            unsigned long        SizeOfUninitializedData;
            unsigned long        AddressOfEntryPoint;
            unsigned long        BaseOfCode;
            uint64_t             ImageBase;
            unsigned long        SectionAlignment;
            unsigned long        FileAlignment;
            uint16_t             MajorOperatingSystemVersion;
            uint16_t             MinorOperatingSystemVersion;
            uint16_t             MajorImageVersion;
            uint16_t             MinorImageVersion;
            uint16_t             MajorSubsystemVersion;
            uint16_t             MinorSubsystemVersion;
            unsigned long        Win32VersionValue;
            unsigned long        SizeOfImage;
            unsigned long        SizeOfHeaders;
            unsigned long        CheckSum;
            uint16_t             Subsystem;
            uint16_t             DllCharacteristics;
            uint64_t             SizeOfStackReserve;
            uint64_t             SizeOfStackCommit;
            uint64_t             SizeOfHeapReserve;
            uint64_t             SizeOfHeapCommit;
            unsigned long        LoaderFlags;
            unsigned long        NumberOfRvaAndSizes;
            IMAGE_DATA_DIRECTORY DataDirectory[num_dir_entries];
        };

        struct IMAGE_OPTIONAL_HEADER32 {
            uint16_t             Magic;
            uint8_t              MajorLinkerVersion;
            uint8_t              MinorLinkerVersion;
            unsigned long        SizeOfCode;
            unsigned long        SizeOfInitializedData;
            unsigned long        SizeOfUninitializedData;
            unsigned long        AddressOfEntryPoint;
            unsigned long        BaseOfCode;
            unsigned long        BaseOfData;
            unsigned long        ImageBase;
            unsigned long        SectionAlignment;
            unsigned long        FileAlignment;
            uint16_t             MajorOperatingSystemVersion;
            uint16_t             MinorOperatingSystemVersion;
            uint16_t             MajorImageVersion;
            uint16_t             MinorImageVersion;
            uint16_t             MajorSubsystemVersion;
            uint16_t             MinorSubsystemVersion;
            unsigned long        Win32VersionValue;
            unsigned long        SizeOfImage;
            unsigned long        SizeOfHeaders;
            unsigned long        CheckSum;
            uint16_t             Subsystem;
            uint16_t             DllCharacteristics;
            unsigned long        SizeOfStackReserve;
            unsigned long        SizeOfStackCommit;
            unsigned long        SizeOfHeapReserve;
            unsigned long        SizeOfHeapCommit;
            unsigned long        LoaderFlags;
            unsigned long        NumberOfRvaAndSizes;
            IMAGE_DATA_DIRECTORY DataDirectory[num_dir_entries];
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

        __forceinline const PEB_T* peb() noexcept
        {
#if defined(_WIN64)
            return reinterpret_cast<const TEB*>(
                       __readgsqword(offsetof(NT_TIB, Self)))
                ->ProcessEnvironmentBlock;
#else
            return reinterpret_cast<const TEB*>(
                       __readfsdword(offsetof(NT_TIB, Self)))
                ->ProcessEnvironmentBlock;
#endif
        }

    } // namespace win

    template<std::uint32_t Hash>
    __forceinline std::uintptr_t find_nocache() noexcept
    {
        const auto* head = reinterpret_cast<const win::LDR_DATA_TABLE_ENTRY_T*>(
            win::peb()->Ldr->InLoadOrderModuleList.Flink);
        std::uintptr_t                     base;
        unsigned long                      i;
        const win::IMAGE_EXPORT_DIRECTORY* ied;

    MODULE_START:
        base = head->DllBase;
        i    = 0u;

        ied = reinterpret_cast<const win::IMAGE_EXPORT_DIRECTORY*>(
            base +
            reinterpret_cast<const win::IMAGE_NT_HEADERS*>(
                base +
                reinterpret_cast<const win::IMAGE_DOS_HEADER*>(base)->e_lfanew)
                ->OptionalHeader.DataDirectory->VirtualAddress);

        if (reinterpret_cast<std::uintptr_t>(ied) != base) {
        IMPORT_START:
            const auto* const name_table =
                reinterpret_cast<const unsigned long*>(base + ied->AddressOfNames) +
                i;
            if (li::detail::hash{}(
                    reinterpret_cast<const char*>(base + *name_table)) == Hash) {
                const auto* const rva_table = reinterpret_cast<const unsigned long*>(
                    base + ied->AddressOfFunctions);

                const auto* const ord_table =
                    reinterpret_cast<const unsigned short*>(
                        base + ied->AddressOfNameOrdinals);

                return base + rva_table[ord_table[i]];
            }
            if (++i != ied->NumberOfNames)
                goto IMPORT_START;
        }
        head = reinterpret_cast<const win::LDR_DATA_TABLE_ENTRY_T*>(
            head->InLoadOrderLinks.Flink);

        goto MODULE_START;
    }

}} // namespace li::detail

#endif // include guard
