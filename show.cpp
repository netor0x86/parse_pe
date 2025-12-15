#include <unordered_map>
#include "show.h"
#include "common.h"

CShowPe::CShowPe(CPE& pe) : m_pe(pe)
{
    std::cout << "show =======>" << std::endl;

    m_pe = pe;
}

void CShowPe::ShowDosHdr()
{
    PIMAGE_DOS_HEADER DosHdr = m_pe.GetDosHdr();
    std::cout << "IMAGE_DOS_HEADER:" << std::endl;
    std::cout << "\t" << "e_magic:" << std::hex << DosHdr->e_magic << std::endl;
    std::cout << "\t" << "e_lfanew:" << std::hex << DosHdr->e_lfanew << std::endl;
}

void CShowPe::ShowPeSignature()
{
    CNtHdr NtHdr = m_pe.GetNtHdr();

    std::cout << "IMAGE_NT_HEADERS" << std::endl;
    std::cout << std::hex << std::setfill('0');
    std::cout << "\t" << std::setw(3) << (&NtHdr.NtHdr.pImgNtHdr32->Signature - (unsigned long *)NtHdr.NtHdr.pImgNtHdr64) << ": Signature:" << std::hex << NtHdr.NtHdr.pImgNtHdr32->Signature << std::endl;
    std::cout << std::dec << std::setfill(' ');
}

void CShowPe::ShowFileHdr()
{
    CNtHdr NtHdr = m_pe.GetNtHdr();

    PIMAGE_FILE_HEADER pFileHdr = &NtHdr.NtHdr.pImgNtHdr32->FileHeader;

    std::cout << "IMAGE_FILE_HEADER" << std::endl;
    
    std::cout << std::hex << std::setfill('0');

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pFileHdr->Machine - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": Machine: " << pFileHdr->Machine << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pFileHdr->NumberOfSections - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": NumberOfSections: " << pFileHdr->NumberOfSections << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pFileHdr->TimeDateStamp - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": TimeDateStamp: " << pFileHdr->TimeDateStamp << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pFileHdr->PointerToSymbolTable - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": PointerToSymbolTable: " << pFileHdr->PointerToSymbolTable << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pFileHdr->NumberOfSymbols - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": NumberOfSymbols: " << pFileHdr->NumberOfSymbols << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pFileHdr->SizeOfOptionalHeader - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": SizeOfOptionalHeader: " << pFileHdr->SizeOfOptionalHeader << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pFileHdr->Characteristics - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": Characteristics: " << pFileHdr->Characteristics << std::endl;

    std::cout << std::dec << std::setfill(' ');
}

void CShowPe::ShowOptHdr32()
{
    CNtHdr NtHdr = m_pe.GetNtHdr();

    PIMAGE_OPTIONAL_HEADER32 pOptHdr = &NtHdr.NtHdr.pImgNtHdr32->OptionalHeader;

    std::cout << std::hex << std::setfill('0');

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->Magic - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": Magic:" << pOptHdr->Magic << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->MajorLinkerVersion - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": MajorLinkerVersion:" << static_cast<int>(pOptHdr->MajorLinkerVersion) << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->MinorLinkerVersion - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": MinorLinkerVersion:" << static_cast<int>(pOptHdr->MinorLinkerVersion) << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->SizeOfCode - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": SizeOfCode:" << pOptHdr->SizeOfCode << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->SizeOfInitializedData - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": SizeOfInitializedData:" << pOptHdr->SizeOfInitializedData << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->SizeOfUninitializedData - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": SizeOfUninitializedData:" << pOptHdr->SizeOfUninitializedData << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->AddressOfEntryPoint - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": AddressOfEntryPoint:" << pOptHdr->AddressOfEntryPoint << std::endl;
    
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->BaseOfCode - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": BaseOfCode:" << pOptHdr->BaseOfCode << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->BaseOfData - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": BaseOfData:" << pOptHdr->BaseOfData << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->ImageBase - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": ImageBase:" << pOptHdr->ImageBase << std::endl;
    
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->SectionAlignment - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": SectionAlignment:" << pOptHdr->SectionAlignment << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->FileAlignment - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": FileAlignment:" << pOptHdr->FileAlignment << std::endl;
    
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->MajorOperatingSystemVersion - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": MajorOperatingSystemVersion:" << pOptHdr->MajorOperatingSystemVersion << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->MinorOperatingSystemVersion - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": MinorOperatingSystemVersion:" << pOptHdr->MinorOperatingSystemVersion << std::endl;
    
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->MajorImageVersion - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": MajorImageVersion:" << pOptHdr->MajorImageVersion << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->MinorImageVersion - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": MinorImageVersion:" << pOptHdr->MinorImageVersion << std::endl;
    
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->MajorSubsystemVersion - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": MajorSubsystemVersion:" << pOptHdr->MajorSubsystemVersion << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->MinorSubsystemVersion - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": MinorSubsystemVersion:" << pOptHdr->MinorSubsystemVersion << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->Win32VersionValue - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": Win32VersionValue:" << pOptHdr->Win32VersionValue << std::endl;
    
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->SizeOfImage - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": SizeOfImage:" << pOptHdr->SizeOfImage << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->SizeOfHeaders - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": SizeOfHeaders:" << pOptHdr->SizeOfHeaders << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->CheckSum - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": CheckSum:" << pOptHdr->CheckSum << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->Subsystem - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": Subsystem:" << pOptHdr->Subsystem << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->DllCharacteristics - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": DllCharacteristics:" << pOptHdr->DllCharacteristics << std::endl;
    
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->SizeOfStackReserve - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": SizeOfStackReserve:" << pOptHdr->SizeOfStackReserve << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->SizeOfStackCommit - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": SizeOfStackCommit:" << pOptHdr->SizeOfStackCommit << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->SizeOfHeapReserve - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": SizeOfHeapReserve:" << pOptHdr->SizeOfHeapReserve << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->SizeOfHeapCommit - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": SizeOfHeapCommit:" << pOptHdr->SizeOfHeapCommit << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->LoaderFlags - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": LoaderFlags:" << pOptHdr->LoaderFlags << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->NumberOfRvaAndSizes - (byte *)NtHdr.NtHdr.pImgNtHdr32) 
            << ": NumberOfRvaAndSizes:" << pOptHdr->NumberOfRvaAndSizes << std::endl;

    std::cout << std::dec << std::setfill(' ');
}

void CShowPe::ShowOptHdr64()
{
    CNtHdr NtHdr = m_pe.GetNtHdr();

    PIMAGE_OPTIONAL_HEADER64 pOptHdr = &NtHdr.NtHdr.pImgNtHdr64->OptionalHeader;

    std::cout << std::hex << std::setfill('0');

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->Magic - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": Magic:" << pOptHdr->Magic << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->MajorLinkerVersion - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": MajorLinkerVersion:" << static_cast<int>(pOptHdr->MajorLinkerVersion) << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->MinorLinkerVersion - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": MinorLinkerVersion:" << static_cast<int>(pOptHdr->MinorLinkerVersion) << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->SizeOfCode - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": SizeOfCode:" << pOptHdr->SizeOfCode << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->SizeOfInitializedData - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": SizeOfInitializedData:" << pOptHdr->SizeOfInitializedData << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->SizeOfUninitializedData - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": SizeOfUninitializedData:" << pOptHdr->SizeOfUninitializedData << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->AddressOfEntryPoint - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": AddressOfEntryPoint:" << pOptHdr->AddressOfEntryPoint << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->BaseOfCode - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": BaseOfCode:" << pOptHdr->BaseOfCode << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->ImageBase - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": ImageBase:" << pOptHdr->ImageBase << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->SectionAlignment - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": SectionAlignment:" << pOptHdr->SectionAlignment << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->FileAlignment - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": FileAlignment:" << pOptHdr->FileAlignment << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->MajorOperatingSystemVersion - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": MajorOperatingSystemVersion:" << pOptHdr->MajorOperatingSystemVersion << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->MinorOperatingSystemVersion - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": MinorOperatingSystemVersion:" << pOptHdr->MinorOperatingSystemVersion << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->MajorImageVersion - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": MajorImageVersion:" << pOptHdr->MajorImageVersion << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->MinorImageVersion - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": MinorImageVersion:" << pOptHdr->MinorImageVersion << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->MajorSubsystemVersion - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": MajorSubsystemVersion:" << pOptHdr->MajorSubsystemVersion << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->MinorSubsystemVersion - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": MinorSubsystemVersion:" << pOptHdr->MinorSubsystemVersion << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->Win32VersionValue - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": Win32VersionValue:" << pOptHdr->Win32VersionValue << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->SizeOfImage - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": SizeOfImage:" << pOptHdr->SizeOfImage << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->SizeOfHeaders - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": SizeOfHeaders:" << pOptHdr->SizeOfHeaders << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->CheckSum - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": CheckSum:" << pOptHdr->CheckSum << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->Subsystem - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": Subsystem:" << pOptHdr->Subsystem << std::endl;
    
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->DllCharacteristics - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": DllCharacteristics:" << pOptHdr->DllCharacteristics << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->SizeOfStackReserve - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": SizeOfStackReserve:" << pOptHdr->SizeOfStackReserve << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->SizeOfStackCommit - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": SizeOfStackCommit:" << pOptHdr->SizeOfStackCommit << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->SizeOfHeapReserve - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": SizeOfHeapReserve:" << pOptHdr->SizeOfHeapReserve << std::endl;
    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->SizeOfHeapCommit - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": SizeOfHeapCommit:" << pOptHdr->SizeOfHeapCommit << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->LoaderFlags - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": LoaderFlags:" << pOptHdr->LoaderFlags << std::endl;

    std::cout << "\t" << std::setw(3) 
            << ((byte *)&pOptHdr->NumberOfRvaAndSizes - (byte *)NtHdr.NtHdr.pImgNtHdr64) 
            << ": NumberOfRvaAndSizes:" << pOptHdr->NumberOfRvaAndSizes << std::endl;

    std::cout << std::dec << std::setfill(' ');
}

void CShowPe::ShowOptHdr()
{
    CNtHdr NtHdr = m_pe.GetNtHdr();

    std::cout << "IMAGE_OPTIONAL_HEADER" << std::endl;

    if (m_pe.IsX64())
    {
        ShowOptHdr64();
    }
    else
    {
        ShowOptHdr32();
    }
}

void CShowPe::ShowSection()
{
    PIMAGE_SECTION_HEADER pSecHdr = m_pe.GetSectionHeader();
    WORD wSecNum = m_pe.GetNtHdr().NtHdr.pImgNtHdr32->FileHeader.NumberOfSections;

    std::cout << "IMAGE_SECTION_HEADER" << std::endl;

    std::cout << std::hex << std::setfill('0');

    while (wSecNum > 0)
    {
        std::cout << "\t" << "Name:" << pSecHdr->Name << std::endl;

        std::cout << "\t\t" << "VirtualSize:" << std::setw(8) << pSecHdr->Misc.VirtualSize << "  "
                  << "VirtualAddress:" << std::setw(8) << pSecHdr->VirtualAddress << "  "
                  << "SizeOfRawData:" << std::setw(8) << pSecHdr->SizeOfRawData << "  "
                  << "PointerToRawData:" << std::setw(8) << pSecHdr->PointerToRawData << std::endl;

        std::cout << "\t\t" << "PointerToRelocations:" << std::setw(8)  << pSecHdr->PointerToRelocations << "  "
                  << "PointerToLinenumbers:" << std::setw(8) << pSecHdr->PointerToLinenumbers << "  "
                  << "NumberOfRelocations:" << std::setw(8) << pSecHdr->NumberOfRelocations << "  "
                  << "NumberOfLinenumbers:" << std::setw(8) << pSecHdr->NumberOfLinenumbers << std::endl;

        std::cout << "\t\t" << "Characteristics:" << std::setw(8) << pSecHdr->Characteristics << std::endl;

        wSecNum --;
        pSecHdr ++;
    }

    std::cout << std::dec << std::setfill(' ');
}

void CShowPe::ShowDataDir()
{
    PIMAGE_DATA_DIRECTORY pDataDir = NULL;
    DWORD NumberOfRvaAndSizes = 16;

    if (m_pe.IsX64())
    {
        pDataDir = m_pe.GetNtHdr().NtHdr.pImgNtHdr64->OptionalHeader.DataDirectory;
        NumberOfRvaAndSizes = m_pe.GetNtHdr().NtHdr.pImgNtHdr64->OptionalHeader.NumberOfRvaAndSizes;
    }
    else
    {
        pDataDir = m_pe.GetNtHdr().NtHdr.pImgNtHdr32->OptionalHeader.DataDirectory;
        NumberOfRvaAndSizes = m_pe.GetNtHdr().NtHdr.pImgNtHdr32->OptionalHeader.NumberOfRvaAndSizes;
    }

    std::cout << "IMAGE_DATA_DIRECTORY" << std::endl;
    std::cout << "\t" << "NumberOfRvaAndSizes:" << NumberOfRvaAndSizes << std::endl;
    std::cout << std::hex << std::setfill('0');

    std::cout << "\t" << "IMAGE_DIRECTORY_ENTRY_EXPORT:" << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress << ":" 
                                                         << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size << std::endl;
    std::cout << "\t" << "IMAGE_DIRECTORY_ENTRY_IMPORT:" << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress << ":" 
                                                         << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].Size << std::endl;
    std::cout << "\t" << "IMAGE_DIRECTORY_ENTRY_RESOURCE:" << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress << ":" 
                                                           << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size << std::endl;
    std::cout << "\t" << "IMAGE_DIRECTORY_ENTRY_EXCEPTION:" << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress << ":" 
                                                            << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size << std::endl;
    std::cout << "\t" << "IMAGE_DIRECTORY_ENTRY_SECURITY:" << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress << ":" 
                                                           << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_SECURITY].Size << std::endl;
    std::cout << "\t" << "IMAGE_DIRECTORY_ENTRY_BASERELOC:" << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress << ":" 
                                                            << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size << std::endl;
    std::cout << "\t" << "IMAGE_DIRECTORY_ENTRY_DEBUG:" << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress << ":" 
                                                        << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_DEBUG].Size << std::endl;
    std::cout << "\t" << "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:" << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress << ":" 
                                                               << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size << std::endl;
    std::cout << "\t" << "IMAGE_DIRECTORY_ENTRY_GLOBALPTR:" << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress << ":" 
                                                            << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].Size << std::endl;
    std::cout << "\t" << "IMAGE_DIRECTORY_ENTRY_TLS:" << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress << ":" 
                                                      << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_TLS].Size << std::endl;
    std::cout << "\t" << "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:" << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress << ":" 
                                                              << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size << std::endl;
    std::cout << "\t" << "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:" << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress << ":" 
                                                               << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size << std::endl;
    std::cout << "\t" << "IMAGE_DIRECTORY_ENTRY_IAT:" << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress << ":" 
                                                      << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_IAT].Size << std::endl;
    std::cout << "\t" << "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:" << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress << ":" 
                                                               << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size << std::endl;
    std::cout << "\t" << "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:" << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress << ":" 
                                                                 << std::setw(8) << pDataDir[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size << std::endl;
    
    std::cout << std::dec << std::setfill(' ');
}

void CShowPe::ShowNtHdrs()
{
    ShowPeSignature();
    ShowFileHdr();
    ShowOptHdr();
    ShowDataDir();
    ShowSection();
}

void CShowPe::ShowBaseRelocation()
{
    std::cout << "IMAGE_BASE_RELOCATION" << std::endl;

    PIMAGE_BASE_RELOCATION pBaseReloc = m_pe.GetBaseRelocation();

    if (pBaseReloc == m_pe.GetBase())
    {
        std::cout << "没有重定位表" << std::endl;
        return ;
    }

    std::cout << std::hex << std::setfill('0');

    int iCnt = 0;
    while (pBaseReloc->VirtualAddress != 0 && pBaseReloc->SizeOfBlock != 0)
    {
        int iNum = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        std::cout << iCnt << ":VirtualAddress:" << pBaseReloc->VirtualAddress << " SizeOfBlock:" << pBaseReloc->SizeOfBlock << " Number:" << iNum << std::endl;

        PTYPEOFFSET pTypeOffset = (PTYPEOFFSET)(pBaseReloc + 1);

        for (int i = 0; i < iNum; i ++)
        {
            std::cout << "\t" << pTypeOffset[i].Type << ":" << std::setw(8) << pBaseReloc->VirtualAddress + pTypeOffset[i].offset << std::endl;
        }

        pBaseReloc = (PIMAGE_BASE_RELOCATION)((byte *)pBaseReloc + pBaseReloc->SizeOfBlock);

        iCnt ++;
    }

    std::cout << std::dec << std::setfill(' ');
}

void CShowPe::ShowExportDir()
{
    std::cout << "IMAGE_EXPORT_DIRECTORY" << std::endl;

    PIMAGE_EXPORT_DIRECTORY pExportDir = m_pe.GetExportDir();

    if (pExportDir == NULL)
    {
        std::cout << "没有导出表" << std::endl;
        return ;
    }

    std::cout << "\t" << "Name:" << m_pe.RvaToFa(pExportDir->Name) + (byte *)m_pe.GetBase() << std::endl;
    std::cout << "\t" << "Base:" << pExportDir->Base << std::endl;
    std::cout << "\t" << "NumberOfFunctions:" << pExportDir->NumberOfFunctions << std::endl;
    std::cout << "\t" << "NumberOfNames:" << pExportDir->NumberOfNames << std::endl;

    std::unordered_map<WORD, int> wOrdinals;

    WORD *pOrdinal = (WORD *)((byte *)m_pe.GetBase() + m_pe.RvaToFa(pExportDir->AddressOfNameOrdinals));
    DWORD *pName = (DWORD *)((byte *)m_pe.GetBase() + m_pe.RvaToFa(pExportDir->AddressOfNames));
    DWORD *pFuncs = (DWORD *)((byte *)m_pe.GetBase() + m_pe.RvaToFa(pExportDir->AddressOfFunctions));

    for (int i = 0; i < pExportDir->NumberOfNames; i ++)
    {
        wOrdinals[*pOrdinal] = i;
        pOrdinal ++;
    }

    std::cout << std::hex << std::setfill('0');

    for (int i = 0; i < pExportDir->NumberOfFunctions; i ++)
    {
        auto it = wOrdinals.find(i);
        if (it != wOrdinals.end()) {
            WORD index = it->second;
            std::cout << i + pExportDir->Base 
                << " " << (char *)(m_pe.RvaToFa(pName[index]) + (byte *)m_pe.GetBase()) 
                << " " <<  std::setw(8) << pFuncs[i]
                << std::endl;
        }
        else
        {
            std::cout << i + pExportDir->Base 
                << " " <<  std::setw(8) << pFuncs[i]
                << std::endl;  
        }
    }

    std::cout << std::setfill(' ');
}

void CShowPe::ShowImportDesc()
{
    std::cout << "IMAGE_IMPORT_DESCRIPTOR" << std::endl;

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = m_pe.GetImportDesc();

    while (pImportDesc->OriginalFirstThunk)
    {
        std::cout << "\t" << m_pe.RvaToFa(pImportDesc->Name) + (byte *)m_pe.GetBase() << std::endl;

        if (m_pe.IsX64())
        {
            PIMAGE_THUNK_DATA64 pThunk = (PIMAGE_THUNK_DATA64)(m_pe.RvaToFa(pImportDesc->OriginalFirstThunk) + (byte *)m_pe.GetBase());

            while (pThunk->u1.Ordinal)
            {
                if (!IMAGE_SNAP_BY_ORDINAL64(pThunk->u1.Ordinal))
                {
                    PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(m_pe.RvaToFa(pThunk->u1.Function) + (byte *)m_pe.GetBase());
                    std::cout << "\t\t" << pImportByName->Hint << " " << pImportByName->Name << std::endl;
                }
                else
                {
                    std::cout << "\t\t" << IMAGE_ORDINAL64(pThunk->u1.Ordinal) << std::endl;
                }

                pThunk ++;
            }
        }
        else
        {
            PIMAGE_THUNK_DATA32 pThunk = (PIMAGE_THUNK_DATA32)(m_pe.RvaToFa(pImportDesc->OriginalFirstThunk) + (byte *)m_pe.GetBase());

            while (pThunk->u1.Ordinal)
            {
                if (!IMAGE_SNAP_BY_ORDINAL32(pThunk->u1.Ordinal))
                {
                    PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(m_pe.RvaToFa(pThunk->u1.Function) + (byte *)m_pe.GetBase());
                    std::cout << "\t\t" << pImportByName->Hint << " " << pImportByName->Name << std::endl;
                }
                else
                {
                    std::cout << "\t\t" << IMAGE_ORDINAL32(pThunk->u1.Ordinal) << std::endl;
                }

                pThunk ++;
            } 
        }
        
        pImportDesc ++;
    }    
}

std::string szResName[] = {
        "",
        "Corsor",
        "Bitmap",
        "Icon",
        "Menu",
        "Dialog",
        "String",
        "FontDir",
        "Font",
        "Accelerator",
        "RCDATA",
        "MessageTable",
        "GroupCursor",
        "",
        "GroupIcon",
        "",
        "Version",
        "DLGINCLUDE",
        "",
        "PLUGPLAY",
        "VXD",
        "ANICURSOR",
        "ANIICON"
        "HTML",
        "MANIFEST"
};

/**
 * 资源相关的结构：
 *      IMAGE_RESOURCE_DIRECTORY
 *      IMAGE_RESOURCE_DIRECTORY_ENTRY
 *      IMAGE_RESOURCE_DATA_ENTRY
 * 根目录 -> 资源类型 -> 资源ID -> 资源代码页
 * 根目录、第二层、第三层中的每个目录都是由一个 IMAGE_RESOURCE_DIRECTORY 结构和紧跟其后的数个 IMAGE_RESOURCE_DIRECTORY_ENTRY 结构组成的，两种结构组成一个目录快
 * 
 * --------------------------------
 * id        |   类型  |  
 * --------------------------------
 * 100       |   ICON  |  "Test.ico"
 * 101       |   WAVE  |  "Test.wav"
 * HelpFile  |   HELP  |  "Test.chm"
 * 102       |   12345 |  "Test.bin"
 * 
 * PIMAGE_RESOURCE_DIRECTORY pRes:    资源的起始地址
 * PIMAGE_RESOURCE_DIRECTORY pResDir: 当前要遍历的资源目录
 * iLevel:                            第几层
 */
void CShowPe::ShowResDir(PIMAGE_RESOURCE_DIRECTORY pRes, PIMAGE_RESOURCE_DIRECTORY pResDir, int iLevel)
{
    int iNumber = pResDir->NumberOfNamedEntries + pResDir->NumberOfIdEntries;

    int iNextLevel = iLevel + 1;

    // 紧跟资源目录结构的就是资源目录入口
    PIMAGE_RESOURCE_DIRECTORY_ENTRY pResEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResDir + 1);
    for (int i = 0; i < iNumber; i ++)
    {
        // 第一层和第二层都是目录
        if (pResEntry->DataIsDirectory)
        {
            PIMAGE_RESOURCE_DIRECTORY pNextResDir = (PIMAGE_RESOURCE_DIRECTORY)((char *)pRes + pResEntry->OffsetToDirectory);

            if (iLevel == 1)
            {
                std::cout << i + 1 << ".";

                if(pResEntry->NameIsString)
                {
                    PIMAGE_RESOURCE_DIR_STRING_U pDirStr = (PIMAGE_RESOURCE_DIR_STRING_U)((char *)pRes + pResEntry->NameOffset);
                    std::cout << "资源类型字符串:" << wstring_to_utf8(pDirStr->NameString) << std::endl;
                }
                else
                {
                    if (pResEntry->Id <= 24)
                    {
                        std::cout << "资源类型:" << pResEntry->Id << ", " << szResName[pResEntry->Id] << std::endl;
                    }
                    else
                    {
                        std::cout << "自定义资源类型:" << pResEntry->Id << std::endl;
                    }
                }
            }
            else if(iLevel == 2)
            {
                std::cout << "  " << i + 1 << "." ;

                if (pResEntry->NameIsString)
                {
                    PIMAGE_RESOURCE_DIR_STRING_U pDirStr = (PIMAGE_RESOURCE_DIR_STRING_U)((char *)pRes + pResEntry->NameOffset);
                    std::cout << "资源字符串:" << wstring_to_utf8(pDirStr->NameString) << std::endl;
                }
                else
                {
                    std::cout << "自定义资源ID:" << pResEntry->Id << std::endl;
                }
            }

            ShowResDir(pRes, pNextResDir, iNextLevel);
        }
        else
        {
            PIMAGE_RESOURCE_DATA_ENTRY pResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((char *)pRes + pResEntry->OffsetToData);
            std::cout << "     " << i + 1 << "."
                      << "资源ID:" << pResEntry->Id
                      << ",代码页:" << pResEntry->Name
                      << std::hex << std::setfill('0') 
                      << ",文件偏移:" << m_pe.RvaToFa(pResDataEntry->OffsetToData)
                      << ",长度（字节）:" << pResDataEntry->Size
                      << std::dec << std::setfill(' ')
                      << std::endl;
        }

        pResEntry ++;
    }
}

void CShowPe::ShowRes()
{
    std::cout << "IMAGE_RESOURCE_DIRECTORY" << std::endl;

    PIMAGE_RESOURCE_DIRECTORY pResDir = m_pe.GetResDir();

    if (pResDir == NULL)
    {
        std::cout << "没有资源表" << std::endl;
        return ;
    }

    ShowResDir(pResDir, pResDir, 1);
}
