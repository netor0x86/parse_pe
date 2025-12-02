#include "common.h"

/**
 * std::wstring 转 std::string
 */
std::string wstring_to_utf8(const std::wstring& wstr)
{
    if (wstr.empty()) return std::string();
    
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), 
                                         nullptr, 0, nullptr, nullptr);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), 
                       &str[0], size_needed, nullptr, nullptr);
    return str;
}
