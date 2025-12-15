#pragma once

#include <windows.h>
#include <string>
#include <dbghelp.h>

#pragma comment(lib, "imagehlp.lib")

class CNtHdr
{
public:
    union
    {
        PIMAGE_NT_HEADERS32 pImgNtHdr32;
        PIMAGE_NT_HEADERS64 pImgNtHdr64;
    } NtHdr;
};

typedef struct _TYPEOFFSET
{
    WORD offset : 12;      // 偏移值
    WORD Type   : 4;       // 重定位属性(方式)
} TYPEOFFSET, *PTYPEOFFSET;

class CPE
{
public:
    CPE();
    ~CPE();

    BOOL OpenFile(std::string StrFileName);
    VOID CloseFile();

    BOOL VerifyPeHdr();
    VOID GetImgHdr();

    BOOL IsX64();

    DWORD GetImageBase();

    PIMAGE_DOS_HEADER GetDosHdr();
    CNtHdr GetNtHdr();
    PIMAGE_SECTION_HEADER GetSectionHeader();
    PIMAGE_IMPORT_DESCRIPTOR GetImportDesc();
    PIMAGE_BASE_RELOCATION GetBaseRelocation();
    PIMAGE_EXPORT_DIRECTORY GetExportDir();
    PIMAGE_RESOURCE_DIRECTORY GetResDir();

public:
    DWORD RvaToFa(DWORD dwRva);
    DWORD FaToRva(DWORD dwFa);

public:
    LPVOID GetBase();

private:
    std::string m_StrFileName;

    BOOL m_IsX64;

    HANDLE m_hFile;
    HANDLE m_hMap;
    LPVOID m_lpBase;

    PIMAGE_DOS_HEADER m_pImgDosHdr;
    PIMAGE_FILE_HEADER m_pImgFileHdr;

    PIMAGE_NT_HEADERS32 m_pImgNtHdr32;
    PIMAGE_NT_HEADERS64 m_pImgNtHdr64;

    PIMAGE_OPTIONAL_HEADER32 m_pImgOptHdr32;
    PIMAGE_OPTIONAL_HEADER64 m_pImgOptHdr64;
    
    PIMAGE_SECTION_HEADER m_pImgSecHdr;

    PIMAGE_IMPORT_DESCRIPTOR m_pImgImportDesc;
    PIMAGE_EXPORT_DIRECTORY m_pImgEptDir;

    ULONGLONG m_ImageBase64;
    DWORD m_ImageBase32;
};
