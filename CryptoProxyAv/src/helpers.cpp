#include <string>
#include <vector>
#include <stdio.h>
#include <windows.h>
#include <winver.h>
#include <psapi.h>
#include <iostream>
#include <tchar.h>

namespace helpers {
	static const char* hexDigits = "0123456789ABCDEF";

	char* hexStr(const uint8_t* data, int dataLen) {
		int bufLen = (dataLen * 2 + 1) * sizeof(char);
		char* buf = (char*)malloc(bufLen);
		char* ptr = buf;
		for (int i = 0; i < dataLen; i++) {
			*ptr++ = hexDigits[((*data) >> 4) & 0xf];
			*ptr++ = hexDigits[(*data++) & 0xf];
		}
		*ptr = 0;
		return buf;
	}

	WCHAR* hexStrW(const uint8_t* data, int dataLen) {
		WCHAR* buf = (WCHAR*)malloc((dataLen * 2 + 1) * sizeof(WCHAR));
		WCHAR* ptr = buf;
		for (int i = 0; i < dataLen; i++, ptr += 2) {
			wsprintf(ptr, L"%02X", data[i]);
		}
		*ptr = 0;
		return buf;
	}

	bool endsWith(std::string const& fullString, std::string const& ending) {
		if (fullString.length() >= ending.length()) {
			return (0 == fullString.compare(fullString.length() - ending.length(), ending.length(), ending));
		}
		else {
			return false;
		}
	}

	void showVersion(wchar_t* title) {
		HANDLE processHandle = NULL;
		WCHAR filename[MAX_PATH];
		wchar_t* version;

		wchar_t* buf = (wchar_t*)malloc((wcslen(title) + 5 * 4 + 3 + 2 + 4) * sizeof(wchar_t));

		processHandle = GetCurrentProcess();
		if (processHandle != NULL) {
			if (GetModuleFileNameEx(processHandle, NULL, filename, MAX_PATH) == 0) {
				OutputDebugString(L"Failed to get module filename.");
				wsprintf(buf, TEXT("%s ?", title));
				version = const_cast<wchar_t*> (L"?");
				goto show;
			}
			CloseHandle(processHandle);
		}
		else {
			OutputDebugString(L"Failed to open process.");
			wsprintf(buf, TEXT("%s ?"));
			version = const_cast<wchar_t*> (L"?");
			goto show;
		}

		{
			DWORD  verHandle = 10;
			UINT   size = 0;
			LPBYTE lpBuffer = NULL;
			DWORD  verSize = GetFileVersionInfoSize(filename, &verHandle);
			if (verSize != NULL) {
				LPVOID verData = new char[verSize];

				if (GetFileVersionInfo(filename, verHandle, verSize, verData)) {
					BOOL result = VerQueryValue(verData, TEXT("\\"), (VOID FAR * FAR*) & lpBuffer, &size);
					if (result) {
						if (size) {
							VS_FIXEDFILEINFO* verInfo = (VS_FIXEDFILEINFO*)lpBuffer;
							if (verInfo->dwSignature == 0xfeef04bd) {
								swprintf(buf, 100, L"%s %d.%d.%d.%d", title,
									(verInfo->dwFileVersionMS >> 16) & 0xffff,
									(verInfo->dwFileVersionMS >> 0) & 0xffff,
									(verInfo->dwFileVersionLS >> 16) & 0xffff,
									(verInfo->dwFileVersionLS >> 0) & 0xffff);
							}
						}
					}
				}
				delete[] verData;
			}
		}
	show:
		MessageBox(NULL, buf, TEXT("О программе"), MB_OK);
		free(buf);
	}

	std::vector<unsigned char> base64Decode(const std::string& encodedString) {
		// Создаем таблицу декодирования Base64
		const std::string base64Chars =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

		std::vector<unsigned char> decodedBytes;
		int padding = 0;
		unsigned int value = 0;
		int count = 0;

		// Проверяем и добавляем байты в декодированный массив
		for (char c : encodedString) {
			if (c == '=')
				padding++;
			else {
				size_t index = base64Chars.find(c);
				if (index != std::string::npos) {
					value = (value << 6) | index;
					count++;
					if (count == 4) {
						decodedBytes.push_back((value >> 16) & 0xFF);
						decodedBytes.push_back((value >> 8) & 0xFF);
						decodedBytes.push_back(value & 0xFF);
						value = 0;
						count = 0;
					}
				}
			}
		}

		// Обрабатываем последние неполные блоки
		if (count > 0) {
			value <<= 6 * (4 - count);
			value >>= 8 * (4 - count);
			for (int i = 0; i < count - 1; i++)
				decodedBytes.push_back((value >> (8 * (2 - i))) & 0xFF);
		}

		// Удаляем паддинг, если присутствует
		if (padding > 0)
			decodedBytes.resize(decodedBytes.size() - padding);

		return decodedBytes;
	}


	void MyHandleError(const wchar_t* psz) {
		_ftprintf(stderr, TEXT("An error occurred in the program. \n"));
		_ftprintf(stderr, TEXT("%ls\n"), psz);
		_ftprintf(stderr, TEXT("Error number %x.\n"), GetLastError());
		_ftprintf(stderr, TEXT("Program terminating. \n"));
		exit(1);
	}
}