#include <windows.h>
#include <stdio.h>
#include "structs.h"

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

void XOR(char* data, size_t data_len, char* key, size_t key_len) {
	int j;
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}