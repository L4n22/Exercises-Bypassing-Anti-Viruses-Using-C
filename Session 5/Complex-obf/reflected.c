#include<windows.h>
#include<stdio.h>

__declspec(dllexport) int CreateMessage(){
	//user32.dll
	MessageBoxA(NULL ,"Hola!!!", "Reflected!!!", 0);
	//flujo x
	return 0;
}