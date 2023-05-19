#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <cryptuiapi.h>
#include <bcrypt.h>
#include <stdint.h>

// https://learn.microsoft.com/en-us/windows/win32/seccng/signing-data-with-cng
// https://learn.microsoft.com/en-us/windows/win32/seccng/creating-a-hash-with-cng
//void hash(const wchar_t * algorithmName, const wchar_t* providerName) {
//	BCRYPT_ALG_HANDLE hAlg = NULL;
//	BCRYPT_HASH_HANDLE      hHash = NULL;
//	DWORD cbHashObject = 0, cbHash = 0, cbData = 0;
//	PBYTE pbHash = NULL;
//	PBYTE pbHashObject = NULL;
//
//	// ¿Î„ÓËÚÏ˚: "—“¡ 1176.1",  "—“¡ 34.101.31"
//	NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, algorithmName, providerName, 0);
//	if (!BCRYPT_SUCCESS(status)) {
//		wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
//		goto Cleanup;
//	}
//
//	//calculate the size of the buffer to hold the hash object
//	status = BCryptGetProperty(
//		hAlg,
//		BCRYPT_OBJECT_LENGTH,
//		(PBYTE)&cbHashObject,
//		sizeof(DWORD),
//		&cbData,
//		0);
//	if (!BCRYPT_SUCCESS(status))
//	{
//		wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
//		goto Cleanup;
//	}
//
//	//allocate the hash object on the heap
//	pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
//	if (NULL == pbHashObject)
//	{
//		wprintf(L"**** memory allocation failed\n");
//		goto Cleanup;
//	}
//	//create a hash
//	status = BCryptCreateHash(
//		hAlg,
//		&hHash,
//		pbHashObject,
//		cbHashObject,
//		NULL,
//		0,
//		0);
//	if (!BCRYPT_SUCCESS(status))
//	{
//		wprintf(L"**** Error 0x%x returned by BCryptCreateHash\n", status);
//		goto Cleanup;
//	}
//
//	//hash some data
//	status = BCryptHashData(hHash, (PBYTE)rgbMsg, sizeof(rgbMsg), 0);
//	if (!BCRYPT_SUCCESS(status))
//	{
//		wprintf(L"**** Error 0x%x returned by BCryptHashData\n", status);
//		goto Cleanup;
//	}
//
//	//close the hash
//	status = BCryptFinishHash(hHash, pbHash, cbHash, 0);
//	if (!BCRYPT_SUCCESS(status))
//	{
//		wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
//		goto Cleanup;
//	}
//
//	wprintf(L"Success!\n");
//Cleanup:
//	if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
//	if (hHash) BCryptDestroyHash(hHash);
//	if (pbHashObject) HeapFree(GetProcessHeap(), 0, pbHashObject);
//	if (pbHash) HeapFree(GetProcessHeap(), 0, pbHash);
//}



