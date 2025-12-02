#pragma once
#include <string>
#include <windows.h>

/**
 * std::wstring 转 std::string
 */
std::string wstring_to_utf8(const std::wstring& wstr);
