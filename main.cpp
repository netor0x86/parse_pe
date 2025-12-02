#include "pe.h"
#include "show.h"

int main(int argc, char* argv[])
{
    CPE pe;

    std::cout << "hello pe" << std::endl;

    // if (!pe.OpenFile("x96dbg.exe"))
    // if (!pe.OpenFile("pe.exe"))
    if (!pe.OpenFile(argv[1]))
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

    pe.CloseFile();
    return 0;
}
