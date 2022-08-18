#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#OPCODES_SIZE 21

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        printf("[*] Usage: %s NTDLL_FUNCTION", argv[0]);
        exit(0);
    }

    HMODULE loadLibrary = LoadLibraryA("ntdll.dll");
    char* procAddress = GetProcAddress(loadLibrary, argv[1]);
    for (int i = 0; i < OPCODES_SIZE; i++) {
		printf("%02X ", procAddress[i]);
	}
   
    return 0;
}