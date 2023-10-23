#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <cryptuiapi.h>
#include <bcrypt.h>



void enumAlgorithms() {
	ULONG algCount = 0;
	BCRYPT_ALGORITHM_IDENTIFIER *algIds = NULL;
	NTSTATUS status = BCryptEnumAlgorithms(BCRYPT_RNG_OPERATION, &algCount, &algIds, 0);
	if (BCRYPT_SUCCESS(status)) {
		printf("success\n");
		for (ULONG i = 0; i < algCount; i++) {
			printf("Name: %S, dwClass: %ld, dwFlags: %ld\n", algIds[i].pszName, algIds[i].dwClass, algIds[i].dwFlags);
		}
	}
	if (algIds != NULL) {
		BCryptFreeBuffer(algIds);
	}
}