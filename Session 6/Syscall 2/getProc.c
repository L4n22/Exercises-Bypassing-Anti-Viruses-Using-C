#include <windows.h>
#include <winternl.h>
#include <stdio.h>


#define OPCODES_SIZE 21

int len(char *string);

void concatString(char string1[], char string2[], char* string3);

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        printf("[*] Usage: %s NTDLL_FUNCTION", argv[0]);
        exit(0);
    }

    char *tempEnv = getenv("TEMP");
    int tempEnvSize = lenString(tempEnv);
    char *dllNameFile = "\\temp.dll";
    int dllFileSize = lenString(dllNameFile);
    int totalSize = tempEnvSize + dllFileSize;
    char *tempPath = malloc(sizeof(char) * (totalSize + 1)); 
    concatString(tempEnv, dllNameFile, tempPath);
    CopyFileA("C:\\Windows\\System32\\ntdll.dll", tempPath, FALSE);
    HANDLE loadLibr = LoadLibraryA(tempPath);
    char* procAddress = GetProcAddress(loadLibr, argv[1]);
    for (int i = 0; i < OPCODES_SIZE; i++) {
		printf("%02X ", *(BYTE *)(procAddress + i));
	}
    
    free(tempPath);
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