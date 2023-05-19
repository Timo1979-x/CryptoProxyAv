#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <cryptuiapi.h>
#include <bcrypt.h>
#include <stdint.h>
#include "helpers.h"
#include <vector>
#include <iostream>

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

static const BYTE rgbMsg[] =
{
    0x61, 0x62, 0x63
};

void testHash(const wchar_t* algorithmName, const wchar_t* providerName) {

    BCRYPT_ALG_HANDLE       hAlg = NULL;
    BCRYPT_HASH_HANDLE      hHash = NULL;
    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    DWORD                   cbData = 0,
        cbHash = 0,
        cbHashObject = 0;
    PBYTE                   pbHashObject = NULL;
    PBYTE                   pbHash = NULL;

    //open an algorithm handle
    if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(
        &hAlg,
        algorithmName,
        providerName,
        0))) {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }

    //calculate the size of the buffer to hold the hash object
    if (!BCRYPT_SUCCESS(status = BCryptGetProperty(
        hAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbHashObject,
        sizeof(DWORD),
        &cbData,
        0))) {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the hash object on the heap
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    if (NULL == pbHashObject) {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    //calculate the length of the hash
    if (!BCRYPT_SUCCESS(status = BCryptGetProperty(
        hAlg,
        BCRYPT_HASH_LENGTH,
        (PBYTE)&cbHash,
        sizeof(DWORD),
        &cbData,
        0))) {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the hash buffer on the heap
    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
    if (NULL == pbHash) {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    //create a hash
    if (!BCRYPT_SUCCESS(status = BCryptCreateHash(
        hAlg,
        &hHash,
        pbHashObject,
        cbHashObject,
        NULL,
        0,
        0))) {
        wprintf(L"**** Error 0x%x returned by BCryptCreateHash\n", status);
        goto Cleanup;
    }


    //hash some data
    if (!BCRYPT_SUCCESS(status = BCryptHashData(
        hHash,
        (PBYTE)rgbMsg,
        sizeof(rgbMsg),
        0))) {
        wprintf(L"**** Error 0x%x returned by BCryptHashData\n", status);
        goto Cleanup;
    }

    //close the hash
    if (!BCRYPT_SUCCESS(status = BCryptFinishHash(
        hHash,
        pbHash,
        cbHash,
        0))) {
        wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
        goto Cleanup;
    }


    printf("%s\n", hexStr((uint8_t*)pbHash, cbHash));

    wprintf(L"Success!\n");

Cleanup:

    if (hAlg) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    if (hHash) {
        BCryptDestroyHash(hHash);
    }

    if (pbHashObject) {
        HeapFree(GetProcessHeap(), 0, pbHashObject);
    }

    if (pbHash) {
        HeapFree(GetProcessHeap(), 0, pbHash);
    }

}

void resolveProviders() {
    PCRYPT_PROVIDER_REFS pBuffer = NULL;
    ULONG cbBuffer = 0;
    // The BCryptResolveProviders function obtains a collection of all of the providers that meet the specified criteria.
    NTSTATUS status = BCryptResolveProviders(NULL, BCRYPT_HASH_INTERFACE, NULL, L"Avest CNG Provider", CRYPT_UM, CRYPT_ALL_FUNCTIONS, &cbBuffer, &pBuffer);
    if (BCRYPT_SUCCESS(status)) {

    }
    if (pBuffer != NULL) {
        BCryptFreeBuffer(pBuffer);
    }
}

void testBase64decode() {
    std::string encodedString = "bWGWFXdoU9qiTCJ2Cj7t35hOLIbKd5xm"; // binary data
    // std::string encodedString = "SGVsbG8gd29ybGQh";  // "Hello world!"

    std::vector<unsigned char> decodedBytes = base64Decode(encodedString);

    std::cout << "Decoded bytes: ";
    for (unsigned char byte : decodedBytes)
        std::cout << static_cast<int>(byte) << " ";
    std::cout << std::endl;
}

void listCertificates() {
    // https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-listing-the-certificates-in-a-store
    // 
    //-------------------------------------------------------------------
    // Copyright (C) Microsoft.  All rights reserved.
    // This program lists all of the certificates in a system certificate
    // store and all of the property identifier numbers of those 
    // certificates. It also demonstrates the use of two
    // UI functions. One, CryptUIDlgSelectCertificateFromStore, 
    // displays the certificates in a store
    // and allows the user to select one of them, 
    // The other, CryptUIDlgViewContext,
    // displays the contents of a single certificate.

    //-------------------------------------------------------------------
    // Declare and initialize variables.

    HCERTSTORE       hCertStore;
    PCCERT_CONTEXT   pCertContext = NULL;
    // Available stores:
    // CA - Certification authority certificates.
    // MY - A certificate store that holds certificates with associated private keys.
    // ROOT- Root certificates.
    // SPC - Software Publisher Certificate.
    wchar_t pszNameString[256];
    LPWSTR pszStoreName = const_cast<wchar_t*> (L"MY");
    void* pvData;
    DWORD            cbData;
    DWORD            dwPropId = 0;
    // Zero must be used on the first
    // call to the function. After that,
    // the last returned property identifier is passed.

    //-------------------------------------------------------------------
    //  Begin processing and Get the name of the system certificate store 
    //  to be enumerated. Output here is to stderr so that the program  
    //  can be run from the command line and stdout can be redirected  
    //  to a file.

    /*fprintf(stderr, "Please enter the store name:");
    gets_s(pszStoreName, sizeof(pszStoreName));*/
    fprintf(stderr, "The store name is %ls.\n", pszStoreName);

    //-------------------------------------------------------------------
    // Open a system certificate store.

    if (hCertStore = CertOpenSystemStore(
        NULL,
        pszStoreName)) {
        fprintf(stderr, "The %ls store has been opened. \n", pszStoreName);
    }
    else {
        // If the store was not opened, exit to an error routine.
        MyHandleError(L"The store was not opened.");
    }

    //-------------------------------------------------------------------
    // Use CertEnumCertificatesInStore to get the certificates 
    // from the open store. pCertContext must be reset to
    // NULL to retrieve the first certificate in the store.

    // pCertContext = NULL;

    while (pCertContext = CertEnumCertificatesInStore(
        hCertStore,
        pCertContext)) {
        //-------------------------------------------------------------------
        // A certificate was retrieved. Continue.
        //-------------------------------------------------------------------
        //  Display the certificate.

        //if (CryptUIDlgViewContext(
        //    CERT_STORE_CERTIFICATE_CONTEXT,
        //    pCertContext,
        //    NULL,
        //    NULL,
        //    0,
        //    NULL))
        //{
        //    //     printf("OK\n");
        //}
        //else
        //{
        //    MyHandleError(L"UI failed.");
        //}

        if (CertGetNameString(
            pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            NULL,
            pszNameString,
            128)) {
            printf("\nCertificate for %ls \n", pszNameString);
        }
        else
            fprintf(stderr, "CertGetName failed. \n");

        //-------------------------------------------------------------------
        // Loop to find all of the property identifiers for the specified  
        // certificate. The loop continues until 
        // CertEnumCertificateContextProperties returns zero.

        while (dwPropId = CertEnumCertificateContextProperties(
            pCertContext, // The context whose properties are to be listed.
            dwPropId))    // Number of the last property found.  
                          // This must be zero to find the first 
                          // property identifier.
        {
            //-------------------------------------------------------------------
            // When the loop is executed, a property identifier has been found.
            // Print the property number.

            printf("Property # %d found->", dwPropId);

            //-------------------------------------------------------------------
            // Indicate the kind of property found.

            switch (dwPropId) {
            case CERT_FRIENDLY_NAME_PROP_ID:
            {
                printf("Display name: ");
                break;
            }
            case CERT_SIGNATURE_HASH_PROP_ID:
            {
                printf("Signature hash identifier ");
                break;
            }
            case CERT_KEY_PROV_HANDLE_PROP_ID:
            {
                printf("KEY PROVE HANDLE");
                break;
            }
            case CERT_KEY_PROV_INFO_PROP_ID:
            {
                printf("KEY PROV INFO PROP ID ");
                break;
            }
            case CERT_SHA1_HASH_PROP_ID:
            {
                printf("SHA1 HASH identifier");
                break;
            }
            case CERT_MD5_HASH_PROP_ID:
            {
                printf("md5 hash identifier ");
                break;
            }
            case CERT_KEY_CONTEXT_PROP_ID:
            {
                printf("KEY CONTEXT PROP identifier");
                break;
            }
            case CERT_KEY_SPEC_PROP_ID:
            {
                printf("KEY SPEC PROP identifier");
                break;
            }
            case CERT_ENHKEY_USAGE_PROP_ID:
            {
                printf("ENHKEY USAGE PROP identifier");
                break;
            }
            case CERT_NEXT_UPDATE_LOCATION_PROP_ID:
            {
                printf("NEXT UPDATE LOCATION PROP identifier");
                break;
            }
            case CERT_PVK_FILE_PROP_ID:
            {
                printf("PVK FILE PROP identifier ");
                break;
            }
            case CERT_DESCRIPTION_PROP_ID:
            {
                printf("DESCRIPTION PROP identifier ");
                break;
            }
            case CERT_ACCESS_STATE_PROP_ID:
            {
                printf("ACCESS STATE PROP identifier ");
                break;
            }
            case CERT_SMART_CARD_DATA_PROP_ID:
            {
                printf("SMART_CARD DATA PROP identifier ");
                break;
            }
            case CERT_EFS_PROP_ID:
            {
                printf("EFS PROP identifier ");
                break;
            }
            case CERT_FORTEZZA_DATA_PROP_ID:
            {
                printf("FORTEZZA DATA PROP identifier ");
                break;
            }
            case CERT_ARCHIVED_PROP_ID:
            {
                printf("ARCHIVED PROP identifier ");
                break;
            }
            case CERT_KEY_IDENTIFIER_PROP_ID:
            {
                printf("KEY IDENTIFIER PROP identifier ");
                break;
            }
            case CERT_AUTO_ENROLL_PROP_ID:
            {
                printf("AUTO ENROLL identifier. ");
                break;
            }
            } // End switch.

              //-------------------------------------------------------------------
              // Retrieve information on the property by first getting the 
              // property size. 
              // For more information, see CertGetCertificateContextProperty.

            if (CertGetCertificateContextProperty(
                pCertContext,
                dwPropId,
                NULL,
                &cbData)) {
                //  Continue.
            }
            else {
                // If the first call to the function failed,
                // exit to an error routine.
                MyHandleError(L"Call #1 to GetCertContextProperty failed.");
            }
            //-------------------------------------------------------------------
            // The call succeeded. Use the size to allocate memory 
            // for the property.

            if (pvData = (void*)malloc(cbData)) {
                // Memory is allocated. Continue.
            }
            else {
                // If memory allocation failed, exit to an error routine.
                MyHandleError(L"Memory allocation failed.");
            }
            //----------------------------------------------------------------
            // Allocation succeeded. Retrieve the property data.

            if (CertGetCertificateContextProperty(
                pCertContext,
                dwPropId,
                pvData,
                &cbData)) {
                // The data has been retrieved. Continue.
            }
            else {
                // If an error occurred in the second call, 
                // exit to an error routine.
                MyHandleError(L"Call #2 failed.");
            }
            //---------------------------------------------------------------
            // Show the results.

            printf("The Property Content is %d \n", pvData);

            //----------------------------------------------------------------
            // Free the certificate context property memory.

            free(pvData);
        }  // End inner while.
    } // End outer while.

      //-------------------------------------------------------------------
      // Select a new certificate by using the user interface.

    if (!(pCertContext = CryptUIDlgSelectCertificateFromStore(
        hCertStore,
        NULL,
        NULL,
        NULL,
        CRYPTUI_SELECT_LOCATION_COLUMN,
        0,
        NULL))) {
        MyHandleError(L"Select UI failed.");
    }


    //-------------------------------------------------------------------
    // Clean up.

    CertFreeCertificateContext(pCertContext);
    CertCloseStore(hCertStore, 0);
    printf("The function completed successfully. \n");
}


