#include "show.h"

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

void CShowPe::ShowNtHdrs()
{
    ShowPeSignature();
    ShowFileHdr();
    ShowOptHdr();
    ShowSection();
}

void CShowPe::ShowImportDesc()
{
    std::cout << "IMAGE_IMPORT_DESCRIPTOR" << std::endl;

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = m_pe.GetImportDesc();

    while (pImportDesc)
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
