#include "pe.h"
#include "common.h"

CPE::CPE()
{
    m_hFile = INVALID_HANDLE_VALUE;
    m_hMap = NULL;
    m_lpBase = NULL;
}

CPE::~CPE()
{
    CloseFile();
}

PIMAGE_BASE_RELOCATION CPE::GetBaseRelocation()
{
    if (m_IsX64)
    {
        return (PIMAGE_BASE_RELOCATION)(RvaToFa(m_pImgOptHdr64->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) + (byte *)m_lpBase);
    }
    else
    {
        return (PIMAGE_BASE_RELOCATION)(RvaToFa(m_pImgOptHdr32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) + (byte *)m_lpBase);
    }
}

PIMAGE_IMPORT_DESCRIPTOR CPE::GetImportDesc()
{
    if (m_IsX64)
    {
        return (PIMAGE_IMPORT_DESCRIPTOR)(RvaToFa(m_pImgOptHdr64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) + (byte *)m_lpBase);
    }
    else
    {
        return (PIMAGE_IMPORT_DESCRIPTOR)(RvaToFa(m_pImgOptHdr32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) + (byte *)m_lpBase);
    }
}

DWORD CPE::GetImageBase()
{
    return m_IsX64 ? m_ImageBase64 : m_ImageBase32;
}

PIMAGE_RESOURCE_DIRECTORY CPE::GetResDir()
{
    if (m_IsX64)
    {
        DWORD dwResDir = m_pImgOptHdr64->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
        if (dwResDir == 0)
        {
            return NULL;
        }
        return (PIMAGE_RESOURCE_DIRECTORY)(RvaToFa(m_pImgOptHdr64->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress) + (byte *)m_lpBase);
    }
    else
    {
        DWORD dwResDir = m_pImgOptHdr32->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
        if (dwResDir == 0)
        {
            return NULL;
        }
        return (PIMAGE_RESOURCE_DIRECTORY)(RvaToFa(m_pImgOptHdr32->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress) + (byte *)m_lpBase);
    }
}

PIMAGE_EXPORT_DIRECTORY CPE::GetExportDir()
{
    if (m_IsX64)
    {
        DWORD dwExportDir = m_pImgOptHdr64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (dwExportDir == 0)
        {
            return NULL;
        }
        return (PIMAGE_EXPORT_DIRECTORY)(RvaToFa(m_pImgOptHdr64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) + (byte *)m_lpBase);
    }
    else
    {
        DWORD dwExportDir = m_pImgOptHdr32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (dwExportDir == 0)
        {
            return NULL;
        }
        return (PIMAGE_EXPORT_DIRECTORY)(RvaToFa(m_pImgOptHdr32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) + (byte *)m_lpBase);
    }
}

LPVOID CPE::GetBase()
{
    return m_lpBase;
}

DWORD CPE::RvaToFa(DWORD dwRva)
{
    PIMAGE_SECTION_HEADER pSec = NULL;
    PIMAGE_NT_HEADERS pNtHdr = NULL;

    if (m_IsX64)
    {
        pNtHdr = (PIMAGE_NT_HEADERS)m_pImgNtHdr64;
    }
    else
    {
        pNtHdr = (PIMAGE_NT_HEADERS)m_pImgNtHdr32;
    }

    pSec = ImageRvaToSection(pNtHdr, m_lpBase, dwRva);

    return dwRva - pSec->VirtualAddress + pSec->PointerToRawData;
}

DWORD CPE::FaToRva(DWORD dwFa)
{
    return 0;
}

PIMAGE_DOS_HEADER CPE::GetDosHdr()
{
    return m_pImgDosHdr;
}

CNtHdr CPE::GetNtHdr()
{
    CNtHdr NtHdr;

    if (m_IsX64)
    {
        NtHdr.NtHdr.pImgNtHdr64 = m_pImgNtHdr64;
    }
    else
    {
        NtHdr.NtHdr.pImgNtHdr32 = m_pImgNtHdr32;
    }

    return NtHdr;
}

BOOL CPE::IsX64()
{
    return m_IsX64;
}

PIMAGE_SECTION_HEADER CPE::GetSectionHeader()
{
    return m_pImgSecHdr;
}

VOID CPE::GetImgHdr()
{
    m_pImgFileHdr = (PIMAGE_FILE_HEADER)(&m_pImgNtHdr32->FileHeader);

    if (m_pImgNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        m_IsX64 = FALSE;
    }
    else if (m_pImgNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        m_IsX64 = TRUE;
    }

    if (m_IsX64)
    {
        m_pImgNtHdr64 = (PIMAGE_NT_HEADERS64)m_pImgNtHdr32;
        m_pImgNtHdr32 = NULL;
        m_pImgOptHdr64 = (PIMAGE_OPTIONAL_HEADER64)(&m_pImgNtHdr64->OptionalHeader);

        m_ImageBase64 = m_pImgOptHdr64->ImageBase;
    }
    else
    {
        m_pImgOptHdr32 = (PIMAGE_OPTIONAL_HEADER32)(&m_pImgNtHdr32->OptionalHeader);

        m_ImageBase32 = m_pImgOptHdr32->ImageBase;
    }

    m_pImgSecHdr = (PIMAGE_SECTION_HEADER)((BYTE *)m_pImgFileHdr + sizeof(IMAGE_FILE_HEADER) + m_pImgFileHdr->SizeOfOptionalHeader);
}

BOOL CPE::VerifyPeHdr()
{
    if (!m_lpBase)
    {
        return FALSE;
    }

    m_pImgDosHdr = (PIMAGE_DOS_HEADER)m_lpBase;
    if (m_pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
    {
        goto ERR;
    }

    m_pImgNtHdr32 = (PIMAGE_NT_HEADERS32)((BYTE *)m_lpBase + m_pImgDosHdr->e_lfanew);
    if (m_pImgNtHdr32->Signature != IMAGE_NT_SIGNATURE)
    {
        goto ERR;
    }

    GetImgHdr();

    return TRUE;

ERR:
    CloseFile();
    return FALSE;
}

BOOL CPE::OpenFile(std::string StrFileName)
{
    m_StrFileName = StrFileName;

    m_hFile = CreateFile(m_StrFileName.c_str(), 
        GENERIC_READ, 
        FILE_SHARE_READ, 
        NULL, 
        OPEN_EXISTING, 
        FILE_ATTRIBUTE_NORMAL, 
        NULL);
    if (m_hFile == INVALID_HANDLE_VALUE)
    {
        goto Err;
    }

    m_hMap = CreateFileMapping(m_hFile,
        NULL,
        PAGE_READONLY,
        0, 0,
        NULL);
    if (m_hMap == NULL)
    {
        goto Err;
    }

    m_lpBase = MapViewOfFile(m_hMap,
        FILE_MAP_READ,
        0, 0, 0);
    if (m_lpBase == NULL)
    {
        goto Err;
    }

    return TRUE;

Err:
    CloseFile();
    return FALSE;
}

VOID CPE::CloseFile()
{
    if (m_lpBase)
    {
        UnmapViewOfFile(m_lpBase);
    }
    if (m_hMap)
    {
        CloseHandle(m_hMap);
    }
    if (m_hFile)
    {
        CloseHandle(m_hFile);
    }

    m_hFile = INVALID_HANDLE_VALUE;
    m_hMap = NULL;
    m_lpBase = NULL;
}
