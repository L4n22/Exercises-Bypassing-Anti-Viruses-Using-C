#include <windows.h>
#include <stdio.h>

#define BLOCK_SIZE 16

typedef int (*__CreateMessage)();

int decrypt(
    LPVOID ciphertext,
    DWORD ciphertextLength
)
{
    BYTE key[] = {
        0x32, 0x34, 0x12, 0x3,
        0x54, 0x12, 0x97, 0x89,
        0x45, 0x22, 0x11, 0x22,
        0x82, 0x12, 0x43, 0x54
    };

    HCRYPTPROV hCryptProv = 0;
    HCRYPTHASH hCryptHash = 0;
    HCRYPTKEY hCryptKey = 0;


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
        &hCryptKey
    );

    if (!success)
    {
        CryptDestroyHash(hCryptHash);
        return 1;
    }

    success = CryptDecrypt(
        hCryptKey,
        hCryptHash,
        0,
        0,
        ciphertext,
        &ciphertextLength
    );


    return 0;
}





int main(int argc, char* argv[])
{
    HRSRC findResourceDll = FindResourceA(
        NULL,
        MAKEINTRESOURCE(1332),
        "RT_STRING"
    );

    BOOL isZeroReturned = FALSE;
    isZeroReturned = findResourceDll == 0;
    if (isZeroReturned)
    {
        exit(1);
    }

    DWORD sizeResourceDll = SizeofResource(
        NULL,
        findResourceDll
    );

    HGLOBAL loadResourceDll = LoadResource(
        NULL,
        findResourceDll
    );

    isZeroReturned = loadResourceDll == 0;
    if (isZeroReturned)
    {
        exit(1);
    }

    LPVOID resourceDllEncrypt = LockResource(loadResourceDll);
    LPVOID resourceDllDecrypt = malloc(sizeResourceDll);

    isZeroReturned = resourceDllDecrypt == 0;
    if (isZeroReturned)
    {
        exit(1);
    }

    memcpy(
        resourceDllDecrypt,
        resourceDllEncrypt,
        sizeResourceDll
    );

    decrypt(
        resourceDllDecrypt,
        sizeResourceDll
    );

   



    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)resourceDllDecrypt;
    
    printf("e_lfanew: %p \n", dosHeader->e_lfanew);


    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((DWORD_PTR)resourceDllDecrypt + dosHeader->e_lfanew);

    SIZE_T sizeDll = ntHeaders->OptionalHeader.SizeOfImage;
 	//printf("sizeDll \n %x", sizeDll);
    //stack - heap
    //heap
    //malloc - calloc ...
    //winapi 
    // - VirtualAlloc - CopyMemory -> CreateThread, -> local
    // VirtualAllocEx - WriteProcessMemory - CreateRemoteThread -> remote
    LPVOID lpMemory = VirtualAlloc(
    	(LPVOID)ntHeaders->OptionalHeader.ImageBase, 
    	sizeDll, 
    	MEM_RESERVE | MEM_COMMIT, 
    	PAGE_EXECUTE_READWRITE
    );

    if (lpMemory == 0) {
        return 1;
    }

    CopyMemory(lpMemory, resourceDllDecrypt, ntHeaders->OptionalHeader.SizeOfHeaders);


    //load sections into memory
    printf("NumberOfSections: %d\n", ntHeaders->FileHeader.NumberOfSections);
    IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {

		LPVOID sectionBytes = (LPVOID)((DWORD_PTR)resourceDllDecrypt + (DWORD_PTR)sectionHeader->PointerToRawData);
        LPVOID sectionDest = (LPVOID)((DWORD_PTR)lpMemory + (DWORD_PTR)sectionHeader->VirtualAddress);

     
        CopyMemory(sectionDest, sectionBytes, sectionHeader->SizeOfRawData);

        printf("Copied %s\n", sectionHeader->Name);
        sectionHeader++;
    }

    //imgExportDirectory 100 + x
    IMAGE_EXPORT_DIRECTORY* imgExportDirectory = (IMAGE_EXPORT_DIRECTORY*)((DWORD_PTR)lpMemory + ntHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    printf("address exportDirectory: %X\n", imgExportDirectory->AddressOfNames);
    printf("address lpmemory + exportDirectory: %X\n", (DWORD*)((DWORD_PTR)lpMemory + imgExportDirectory->AddressOfNames));
    //ACA VOY
    DWORD* addrNames = (DWORD*)((DWORD_PTR)lpMemory + imgExportDirectory->AddressOfNames);
    DWORD* addrFunction = (DWORD*)((DWORD_PTR)lpMemory + imgExportDirectory->AddressOfFunctions);
    WORD* addrOrdinal = (WORD*)((DWORD_PTR)lpMemory + imgExportDirectory->AddressOfNameOrdinals);

    IMAGE_IMPORT_DESCRIPTOR* imgDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD_PTR)lpMemory + ntHeaders->OptionalHeader.DataDirectory[1].VirtualAddress);
    LPCSTR libName = "";
    while (imgDescriptor->Name != NULL) {
        libName = (LPCSTR)imgDescriptor->Name + (DWORD_PTR)lpMemory;
        printf("%s\n", libName);
        //DLL
        //load DLL
        //printf("%s\n", libName);
        IMAGE_THUNK_DATA* firstThunk;
        HMODULE hLibrary = LoadLibrary(libName); 
        if (hLibrary) 
        {
        	//aca
            firstThunk = (IMAGE_THUNK_DATA*)((DWORD_PTR)lpMemory + imgDescriptor->FirstThunk);
            //printf("FirstThunk: %p\n", firstThunk);

            while (firstThunk->u1.AddressOfData) 
            {
        
                DWORD_PTR importFn = (DWORD_PTR)lpMemory + *(DWORD*)firstThunk;
                printf("importFn: %p\n", importFn);
                LPCSTR n = (LPCSTR)((IMAGE_IMPORT_BY_NAME*)importFn)->Name;
                *(DWORD_PTR*)firstThunk = (DWORD_PTR)GetProcAddress(hLibrary, n);
            	firstThunk++;
            }
        }
        imgDescriptor++;
    }



    __CreateMessage C_CreateMessage = NULL;
    char txtCreateMessage[] = "CreateMessage";
    DWORD fnAddress = -1;
    printf("number of function %d\n", imgExportDirectory->NumberOfFunctions);
    for (size_t index = 0; index < imgExportDirectory->NumberOfFunctions; index++) {
        char* name = (char*)((DWORD_PTR)lpMemory + addrNames[index]);
        fnAddress = addrFunction[addrOrdinal[index]];
        //printf("%ld", index);
        if (strcmp(name, txtCreateMessage) == 0) {
            //printf("[*] Found %s -> %lx\n", name, (DWORD_PTR)lpMemory + fnAddress);
            C_CreateMessage = (__CreateMessage)((DWORD_PTR)lpMemory + addrFunction[addrOrdinal[index]]);
            break;
        }

    }

    if (C_CreateMessage != NULL) {

        int t = C_CreateMessage();
        printf("Success: %d", t);
    }


    free(resourceDllDecrypt);
    return 0;
}