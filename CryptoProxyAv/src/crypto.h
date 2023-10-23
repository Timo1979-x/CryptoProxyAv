#pragma once

namespace crypto {
	uint8_t* hash(const wchar_t* algorithmName, const wchar_t* providerName, PBYTE data, int dataLength, DWORD* cbHash);
	void resolveProviders();
	void testBase64decode();
	void testHash(const wchar_t* algorithmName, const wchar_t* providerName);
	uint8_t* sign(const wchar_t* algorithmName, const wchar_t* providerName, PBYTE data, int dataLength);
	void testSign(const wchar_t* algorithmName, const wchar_t* providerName);
	void enumStorageProviders();
	void getBelarussianAlgIds();
}