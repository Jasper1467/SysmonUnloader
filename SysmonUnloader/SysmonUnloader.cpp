#include <iostream>
#include <xorstr.hpp>

#include "_GetProcAddress.h"

PVOID _GetProcAddress_Wrapper(PVOID BaseAddress, const SHA256String& ModuleName, const SHA256String& ProcedureName)
{
	// Original instructions
	unsigned int x = 0x12345678;
	unsigned int y = 0x87654321;
	if (x == y) {
		x = 0x11111111;
		y = 0x22222222;
	}
	else {
		x = 0x33333333;
		y = 0x44444444;
	}

	// Obfuscated instructions using control flow flattening
	bool bReached = false;
	int i = 0;
	while (!bReached) 
	{
		switch (i)
		{
		case 0:
			if (x == y)
			{
				x = 0x55555555;
				y = 0x66666666;
			}
			break;
		case 1:
			if (x != y) {
				// ReSharper disable once CppAssignedValueIsNeverUsed
				x = 0x77777777;
				// ReSharper disable once CppAssignedValueIsNeverUsed
				y = 0x88888888;
			}
			bReached = true;
			// Use complex control flow structures to make it
			// difficult for the disassembler to track the flow
			// of execution
			for (int j = 0; j < 11; j++)
			{
				if (j % 2 == 0)
				{
					for (int k = 0; k < 15; k++)
					{
						if (k % 2 == 1)
						{
							for (int l = 0; l < 67; l++)
							{
								if (l % 2 == 0)
									return _GetProcAddress(BaseAddress, ModuleName, ProcedureName);

							}
						}
					}
				}
			}
		default:
			break;
		}
		i++;
		if (i > 10)
			break;
	}

	return nullptr;
}

int main()
{
	const PVOID pfnLoadLibrary = _GetProcAddress_Wrapper(nullptr, SHA256String("kernel32.dll"), SHA256String("LoadLibraryA"));
	printf("LoadLibraryA: 0x%p\n", pfnLoadLibrary);

	const HMODULE hModule = reinterpret_cast<HMODULE(__stdcall*)(LPCSTR)>(pfnLoadLibrary)(xorstr_("sysmondrv"));
	printf("sysmondrv: 0x%p\n", hModule);

	const PVOID pfnUnload = _GetProcAddress_Wrapper(hModule, SHA256String("sysmondrv"), SHA256String("Unload"));
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
