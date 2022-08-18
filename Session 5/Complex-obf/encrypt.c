#include <windows.h>
#include <stdio.h>


#define BLOCK_SIZE 16


HCRYPTPROV hCryptProv = 0;
HCRYPTHASH hCryptHash = 0;
HCRYPTKEY hKey = 0;
BYTE iv[BLOCK_SIZE];


int releaseCrypt(
    HCRYPTPROV hCryptProv,
    HCRYPTHASH hCryptHash,
    HCRYPTKEY hKey) {

    if (hCryptHash)
    {
        if (!(CryptDestroyHash(hCryptHash)))
        {
            return 1;
        }
    }

    if (hKey)
    {
        if (!(CryptDestroyKey(hKey)))
        {
            return 1;
        }
    }

    if (hCryptProv)
    {
        if (!(CryptReleaseContext(hCryptProv, 0)))
        {
            return 1;
        }
    }

    return 0;
}




int encrypt(HANDLE hSourceFile, HANDLE hDestinationFile)
{
    BYTE key[] = {
        0x32, 0x34, 0x12, 0x3,
        0x54, 0x12, 0x97, 0x89,
        0x45, 0x22, 0x11, 0x22,
        0x82, 0x12, 0x43, 0x54
    };


    BOOL success = FALSE;

    success = CryptAcquireContextW(
        &hCryptProv,
        NULL,
        NULL,
        PROV_RSA_AES,
        CRYPT_VERIFYCONTEXT
    );

    if (!success)
    {
        return 1;
    }

    success = CryptCreateHash(
        hCryptProv,
        CALG_SHA_256,
        0,
        0,
        &hCryptHash
    );

    if (!success)
    {
        return 1;
    }

    success = CryptHashData(
        hCryptHash,
        key,
        sizeof(key),
        0
    );

    if (!success)
    {
        CryptDestroyHash(hCryptHash);
        return 1;
    }

    success = CryptDeriveKey(
        hCryptProv,
        CALG_AES_256,
        hCryptHash,
        0,
        &hKey
    );

    if (!success)
    {
        CryptDestroyHash(hCryptHash);
        return 1;
    }
	
	
	
	/*
    int i;
    for (i = 0; i < 16; i++)
    {
        if (i > 0) printf(":");
        printf("%02X", iv[i]);
    }
    printf("\n");

    success = CryptGenRandom(
        hCryptProv,
        BLOCK_SIZE,
        iv
    );

    i;
    for (i = 0; i < 16; i++)
    {
        if (i > 0) printf(":");
        printf("%02X", iv[i]);
    }
    printf("\n");


    if (!success)
    {
        return 1;
    }

    success = CryptSetKeyParam(
        hKey,
        KP_IV,
        iv,
        0
    );
	*/

    if (!success)
    {
        return 1;
    }



    DWORD dwBlockLen = 1000 - 1000 % BLOCK_SIZE;
    DWORD dwBufferLen = dwBlockLen;

    PBYTE pbBuffer = (BYTE*)malloc(dwBufferLen);
    if (!pbBuffer)
    {
        free(pbBuffer);
        return 1;
    }

    DWORD dwCount = 0;
    BOOL fEOF = FALSE;
   
    do
    {
        success = ReadFile(
            hSourceFile,
            pbBuffer,
            dwBlockLen,
            &dwCount,
            NULL
        );

        if (!success)
        {
            return 1;
        }

        if (dwCount < dwBlockLen)
        {
            fEOF = TRUE;
        }


        success = CryptEncrypt(
            hKey,
            0,
            fEOF,
            0,
            pbBuffer,
            &dwCount,
            dwBufferLen
        );

        if (!success)
        {
            return 1;
        }

    
        success = WriteFile(
            hDestinationFile,
            pbBuffer,
            dwCount,
            &dwCount,
            NULL
        );

        if (!success)
        {
            return 1;
        }


    } while (!fEOF);

    
    if (pbBuffer) {
        free(pbBuffer);
    }
   
   
    return 0;
}

int main(int argc, char* argv[])
{
    HANDLE hSourceFile = INVALID_HANDLE_VALUE;
    HANDLE hDestinationFile = INVALID_HANDLE_VALUE;

    
    hSourceFile = CreateFile(
        L"C:\\plaintext.txt",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
   
    if (INVALID_HANDLE_VALUE == hSourceFile)
    {
        return 1;
    }

    hDestinationFile = CreateFile(
        L"C:\\ciphertext.txt",
        FILE_WRITE_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (INVALID_HANDLE_VALUE == hDestinationFile)
    {
        return 1;
    }
    

    encrypt(hSourceFile, hDestinationFile);
  

    if (hSourceFile)
    {
        CloseHandle(hSourceFile);
    }

    if (hDestinationFile)
    {
        CloseHandle(hDestinationFile);
    }


    releaseCrypt(hCryptProv, hCryptHash, hKey);
    
    return 0;
}