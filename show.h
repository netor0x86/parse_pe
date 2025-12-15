#pragma once

#include <iostream>
#include <iomanip>
#include "pe.h"

class CShowPe
{
public:
    CShowPe(CPE& pe);

    void ShowDosHdr();
    void ShowPeSignature();
    void ShowFileHdr();
    void ShowOptHdr32();
    void ShowOptHdr64();
    void ShowOptHdr();
    void ShowNtHdrs();
    void ShowDataDir();
    void ShowSection();
    void ShowImportDesc();
    void ShowBaseRelocation();
    void ShowExportDir();
    void ShowRes();

private:
    void ShowResDir(PIMAGE_RESOURCE_DIRECTORY pRes, PIMAGE_RESOURCE_DIRECTORY pResDir, int iLevel);
    
private:
    CPE& m_pe;
};
