#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <cryptuiapi.h>
#include <bcrypt.h>

void describeInterface(ULONG index, PCRYPT_INTERFACE_REG iface) {
    printf("Interface # %ld\n", index);
    printf("\tdwFlags: %d\n", iface->dwFlags);
    printf("\tdwInterface: %d\n", iface->dwInterface);
    if (iface->cFunctions > 0) {
        printf("\tFunctions:");
        for (ULONG i = 0; i < iface->cFunctions; i++) {
            printf("\t\t%S, ", iface->rgpszFunctions[i]);
        }
        printf("\n");
    }
}

void describeRegistrations(const wchar_t* title, PCRYPT_IMAGE_REG reg) {
    printf("%S\npszImage: %S\n", title, reg->pszImage);
    if (reg->cInterfaces > 0) {
        for (ULONG j = 0; j < reg->cInterfaces; j++) {
            describeInterface(j, reg->rgpInterfaces[j]);
        }
    }
}

// https://learn.microsoft.com/en-us/windows/win32/seccng/using-the-cryptography-configuration-features-of-cng
void EnumProviders1()
{
    NTSTATUS status;
    ULONG cbBuffer = 0;
    PCRYPT_PROVIDERS pBuffer = NULL;

    /*
    Get the providers, letting the BCryptEnumRegisteredProviders
    function allocate the memory.
    */
    status = BCryptEnumRegisteredProviders(&cbBuffer, &pBuffer);

    if (BCRYPT_SUCCESS(status))
    {
        if (pBuffer != NULL)
        {
            // Enumerate the providers.
            for (ULONG i = 0; i < pBuffer->cProviders; i++)
            {
                printf("========== %S ==========\n", pBuffer->rgpszProviders[i]);
                ULONG cbRegBuffer = 0;
                PCRYPT_PROVIDER_REG pRegBuffer = NULL;
                status = BCryptQueryProviderRegistration(
                    pBuffer->rgpszProviders[i],
                    CRYPT_UM,
                    BCRYPT_CIPHER_INTERFACE,
                    &cbRegBuffer,
                    &pRegBuffer
                    );
                if (BCRYPT_SUCCESS( status)) {
                    if (pRegBuffer->cAliases > 0) {
                        printf("Aliases: ");
                        for (ULONG j = 0; j < pRegBuffer->cAliases; j++) {
                            printf("%S, ", pRegBuffer->rgpszAliases[j]);
                        }
                        printf("\n");
                    }

                    if (pRegBuffer->pUM != NULL) {
                        describeRegistrations(L"registration information for the user mode provider:", pRegBuffer->pUM);
                    }
                    if (pRegBuffer->pKM != NULL) {
                        describeRegistrations(L"registration information for the kernel mode provider:", pRegBuffer->pKM);
                    }
                }
                if (pRegBuffer != NULL) {
                    BCryptFreeBuffer(pRegBuffer);
                }
            }
        }
    }
    else
    {
        printf("BCryptEnumRegisteredProviders failed with error "
            "code 0x%08x\n", status);
    }

    if (NULL != pBuffer)
    {
        /*
        Free the memory allocated by the
        BCryptEnumRegisteredProviders function.
        */
        BCryptFreeBuffer(pBuffer);
    }
}
