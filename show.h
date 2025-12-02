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
    void ShowSection();

private:
    CPE& m_pe;
};
