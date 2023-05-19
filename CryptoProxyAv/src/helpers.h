#pragma once
#include <string>
#include <vector>

bool endsWith(std::string const& fullString, std::string const& ending);
char* hexStr(const uint8_t* data, int len);
void showVersion(wchar_t* title);
std::vector<unsigned char> base64Decode(const std::string& encodedString);
void MyHandleError(const wchar_t* psz);
