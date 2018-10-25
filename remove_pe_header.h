#pragma once

#include <Windows.h>
int remove_pe_header ( ) {
	BOOL bProtect = FALSE;
	DWORD dwBaseAddress = ( DWORD )GetModuleHandle ( NULL );
	DWORD dwProtect = 0;
	DWORD dwSizeOfHeaders = 0;
	PIMAGE_DOS_HEADER pDosHeader = ( PIMAGE_DOS_HEADER )dwBaseAddress;
	PIMAGE_NT_HEADERS pNtHeader = ( PIMAGE_NT_HEADERS )( ( DWORD )pDosHeader + ( DWORD )pDosHeader->e_lfanew );

	//Check for MZ header
	if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
		return 1;
	}
	//check for PE header
	if ( pNtHeader->Signature != IMAGE_NT_SIGNATURE ) {
		return 1;
	}

	//get size of headers so we know how much to zero
	if ( pNtHeader->FileHeader.SizeOfOptionalHeader ) {
		dwSizeOfHeaders = pNtHeader->OptionalHeader.SizeOfHeaders;

		//make page writeable
		bProtect = VirtualProtect ( ( LPVOID )dwBaseAddress, dwSizeOfHeaders, PAGE_EXECUTE_READWRITE, &dwProtect );
		if ( bProtect == FALSE ) {
			return 1;
		}

		//zero out headers
		RtlZeroMemory ( ( LPVOID )dwBaseAddress, dwSizeOfHeaders );

		bProtect = VirtualProtect ( ( LPVOID )dwBaseAddress, dwSizeOfHeaders, dwProtect, &dwProtect );
		if ( bProtect == FALSE ) {
			return 1;
		}
	}
	return 0;

}
