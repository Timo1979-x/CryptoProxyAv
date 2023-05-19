#include <windows.h>
#include <winver.h>
#include <psapi.h>
#include <stdio.h>
#include <iostream>

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

bool endsWith(std::string const& fullString, std::string const& ending) {
	if (fullString.length() >= ending.length()) {
		return (0 == fullString.compare(fullString.length() - ending.length(), ending.length(), ending));
	}
	else {
		return false;
	}
}