#include "pe.h"
#include "show.h"

int main(int argc, char* argv[])
{
    CPE pe;

    if (!pe.OpenFile(argv[1]))
    // if (!pe.OpenFile("pe.exe"))
    // if (!pe.OpenFile("x96dbg.exe"))
    // if (!pe.OpenFile("vulkan-1.dll"))
    {
        std::cout << "OpenFile Error" << std::endl;
        pe.CloseFile();
        return -1;
    }
    
    std::cout << "OpenFile Successful" << std::endl;

    if (!pe.VerifyPeHdr())
    {
        std::cout << "VerifyPeHdr Error" << std::endl;
        
        pe.CloseFile();
        return -1;
    }
    
    std::cout << "VerifyPeHdr Successful" << std::endl;
    auto bit = pe.IsX64() ? 64 : 32;
    std::cout << "File bit:" << bit << std::endl;

    CShowPe show(pe);
    show.ShowDosHdr();
    show.ShowNtHdrs();
    show.ShowImportDesc();
    // show.ShowBaseRelocation();
    show.ShowExportDir();

    pe.CloseFile();
    return 0;
}
