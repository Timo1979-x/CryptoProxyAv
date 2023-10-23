#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <cryptuiapi.h>
#include <string>
#include <tchar.h>
#include "CryptoTest.h"

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "cryptui.lib")
#pragma comment (lib, "Bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

void EnumProviders1();
//void hash(const wchar_t *, const wchar_t*);
// void hash();
void info();
void enumAlgorithms();
char * hexStr(const uint8_t* data, int len);

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

void main(void)
{
    //listCertificates();
    // EnumProviders1();
    // Алгоритмы: "СТБ 1176.1",  "СТБ 34.101.31", провайдер:  L"Avest CNG Provider"
    //hash(L"СТБ 34.101.31", L"Avest CNG Provider");
    // hash(BCRYPT_SHA256_ALGORITHM, NULL);
    // hash();
    //enumAlgorithms();
    //info();
    
    //uint8_t x[] = { 0, 1, 10, 11 };
    //printf("%s\n", hexStr((uint8_t *)&x, sizeof(x)));
}

