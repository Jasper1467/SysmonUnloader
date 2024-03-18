#pragma once
#include <Windows.h>

#include <compile_time_hash.hpp>
#include <xorstr.hpp>

inline PIMAGE_NT_HEADERS GetNtHeaders(PVOID BaseAddress)
{
	const auto DosHeader = static_cast<PIMAGE_DOS_HEADER>(BaseAddress);
	return reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<ULONG_PTR>(BaseAddress) + DosHeader->e_lfanew);
}

inline PIMAGE_SECTION_HEADER GetSectionHeader(PIMAGE_NT_HEADERS NtHeaders, const SHA256String& SectionName)
{
	PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);
	for (WORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
	{
		if (SHA256String(reinterpret_cast<CHAR*>(SectionHeader->Name)) == SectionName)
			return SectionHeader;

			SectionHeader++;
	}

	return nullptr;
}

inline PVOID _GetProcAddress(PVOID BaseAddress, const SHA256String& ModuleName, const SHA256String& ProcedureName)
{
	PIMAGE_NT_HEADERS NtHeaders = GetNtHeaders(BaseAddress);
	PIMAGE_SECTION_HEADER SectionHeader = GetSectionHeader(NtHeaders, SHA256String(".idata"));
	if (SectionHeader == nullptr)
		SectionHeader = GetSectionHeader(NtHeaders, SHA256String(".rdata"));
	if (SectionHeader == nullptr)
		return nullptr;
	auto ImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<ULONG_PTR>(BaseAddress) + SectionHeader->VirtualAddress);
	while (ImportDescriptor->Name)
	{
		if (const auto Module = reinterpret_cast<PCHAR>(reinterpret_cast<ULONG_PTR>(BaseAddress) + ImportDescriptor->Name);
			SHA256String(Module) == ModuleName)
		{
			auto OriginalFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<ULONG_PTR>(BaseAddress) + ImportDescriptor->OriginalFirstThunk);
			auto FirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<ULONG_PTR>(BaseAddress) + ImportDescriptor->FirstThunk);
			while (OriginalFirstThunk->u1.AddressOfData)
			{
				if (const auto ImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<ULONG_PTR>(BaseAddress)
					+ OriginalFirstThunk->u1.AddressOfData); SHA256String(ImportByName->Name) == ProcedureName)
					return &FirstThunk->u1.Function;

				OriginalFirstThunk++;
				FirstThunk++;
			}
		}
		ImportDescriptor++;
	}
	return nullptr;
}