
#include "../cryptor_sig.h"

#include <Windows.h>
#include <stdio.h>
#include <string>
#include <array>

#define BUF_SIZE 2560
#define KEY 0x0F

/*
* Declare as SEGMENT_INFO blug;
* use pointer in funciton as void example(SEGMENT_INFO_PTR blugptr);
*/
typedef struct SEGMENT_INFO {
	DWORD moduleBase;
	DWORD memorySegmentOffset;
	DWORD fileSegmentOffset;
	DWORD fileSegmentSize;
} *SEGMENT_INFO_PTR;


bool BaseAddress ( char * file, HANDLE *hFile, HANDLE *hMapFile, LPVOID *lpFileBase ) {
	//HANDLE hMapFile;
	//LPCSTR pBuf;
	//HANDLE hFile = INVALID_HANDLE_VALUE;

	*hFile = CreateFileA ( file,
						   GENERIC_READ | GENERIC_WRITE,
						   FILE_SHARE_READ | FILE_SHARE_WRITE,
						   NULL,
						   OPEN_EXISTING,
						   FILE_ATTRIBUTE_NORMAL,
						   0 );

	if ( hFile == INVALID_HANDLE_VALUE )
	{
		printf ( "Couldn't open file with CreateFile()\n" );
		return false;
	}

	*hMapFile = CreateFileMappingA ( *hFile,
									 NULL,
									 PAGE_READWRITE,
									 0,
									 BUF_SIZE,
									 NULL );

	if ( *hMapFile == 0 )
	{
		CloseHandle ( *hFile );
		printf ( "Couldn't open file mapping with CreateFileMapping()\n" );
		return false;
	}

	*lpFileBase = ( LPSTR )MapViewOfFile ( *hMapFile,
										   FILE_MAP_ALL_ACCESS,
										   0,
										   0,
										   BUF_SIZE );

	if ( *lpFileBase == NULL )
	{
		CloseHandle ( *hMapFile );
		CloseHandle ( *hFile );
		printf ( "Could not map view of file (%d).\n",
				 GetLastError ( ) );
		return false;
	}

	return true;
}


/**
* Look for sectionName segment in mapped file
* addrInfo will be filled with the segment information
*/
void TraverseSectionHeaders
(
	PIMAGE_SECTION_HEADER section,
	DWORD nSections,
	SEGMENT_INFO_PTR addrInfo,
	char * sectionName
)
{
	DWORD i;
	/* Copy pointer to initial section (so this function can be called several times) */
	PIMAGE_SECTION_HEADER localSection = section;
	printf ( "\n\nTraverseSectionHeaders: searching for segment %s headers\n", sectionName );
	for ( i = 0; i<nSections; i++ )
	{
		printf ( "     ====================     \n" );
		printf ( "\tName:			%s\n", ( *section ).Name );

		if ( strcmp ( ( char * )( *section ).Name, sectionName ) == 0 ) {
			( *addrInfo ).fileSegmentOffset = ( *section ).PointerToRawData; /* Location of segment in binary file*/
			( *addrInfo ).fileSegmentSize = ( *section ).SizeOfRawData; /* Size of segment */
			( *addrInfo ).memorySegmentOffset = ( *section ).VirtualAddress; /* Offset of segment in memory at runtime */
			return;
		}

		section = section + 1;
	}
	return;
}

void getSegmentsInfo ( LPVOID baseAddress, SEGMENT_INFO_PTR codeSegment, SEGMENT_INFO_PTR stubSegment )
{
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS peHeader;
	IMAGE_OPTIONAL_HEADER optionalHeader;

	dosHeader = ( PIMAGE_DOS_HEADER )baseAddress;
	if ( ( ( *dosHeader ).e_magic ) != IMAGE_DOS_SIGNATURE )
	{
		printf ( "getSegmentsInfo: Dos signature not matched\n" );
		return;
	}
	printf ( "getSegmentsInfo: Dos signature=%X\n", ( *dosHeader ).e_magic );

	peHeader = ( PIMAGE_NT_HEADERS )( ( DWORD )baseAddress + ( *dosHeader ).e_lfanew );
	if ( ( ( *peHeader ).Signature ) != IMAGE_NT_SIGNATURE )
	{
		printf ( "getSegmentsInfo: PE signature not matched\n" );
		return;
	}
	printf ( "getSegmentsInfo: PE signature=%X\n", ( *peHeader ).Signature );

	optionalHeader = ( *peHeader ).OptionalHeader;
	if ( ( optionalHeader.Magic ) != 0x10B )
	{
		printf ( "getSegmentsInfo: Optional header magic number does not match\n" );
		return;
	}
	printf ( "getSegmentsInfo: OPtional header magic nb=%X\n", optionalHeader.Magic );

	( *codeSegment ).moduleBase = optionalHeader.ImageBase;
	( *stubSegment ).moduleBase = optionalHeader.ImageBase;

	TraverseSectionHeaders ( IMAGE_FIRST_SECTION ( peHeader ), ( *peHeader ).FileHeader.NumberOfSections, codeSegment, CODE_SEG_NAME );
	TraverseSectionHeaders ( IMAGE_FIRST_SECTION ( peHeader ), ( *peHeader ).FileHeader.NumberOfSections, stubSegment, STUB_SEG_NAME );

	return;
}

/**
* Encrypt .code segment bytes in the given file
*/
void cipherBytes ( char* fileName, SEGMENT_INFO_PTR addrInfo )
{
	DWORD fileOffset;
	DWORD nbytes;
	BYTE  key[ ] = { 0x13, 0x37, 0xDE, 0xAD, 0xBE, 0xEF };

	FILE* fptr;
	BYTE *buffer;
	DWORD nItems;
	DWORD i;
	int keyLength = 6;
	int cpt = 0;

	fileOffset = addrInfo->fileSegmentOffset;
	nbytes = addrInfo->fileSegmentSize;
	/* Allocate memory in buffer that will store content of segment */
	buffer = ( BYTE* )malloc ( nbytes );
	if ( buffer == NULL )
	{
		printf ( "cipherBytes: malloc error \n" );
		return;
	}

	/* Open binary file */
	fptr = fopen ( fileName, "r+b" );
	if ( fptr == NULL )
	{
		printf ( "cipherBytes: fopen error \n" );
		return;
	}
	/* Seek .code section using calculated offset and copy content into buffer*/
	if ( fseek ( fptr, fileOffset, SEEK_SET ) != 0 )
	{
		printf ( "cipherBytes: Unable to set file pointer to %ld \n", fileOffset );
		fclose ( fptr );
		return;
	}
	nItems = fread ( buffer, sizeof ( BYTE ), nbytes, fptr );
	if ( nItems < nbytes )
	{
		printf ( "cipherBytes: Trouble reading nItems = %d \n", nItems );
		fclose ( fptr );
		return;
	}
	printf ( "Size of buffer: %d\n", nbytes );
	/* Encrypt buffer */
	for ( i = 0; i < nbytes; i++ )
	{
		buffer[ i ] = buffer[ i ] ^ key[ cpt ];
		cpt = cpt + 1;
		if ( cpt == keyLength )
			cpt = 0;
	}

	/* Replace current .code section in file by encrypted one */
	if ( fseek ( fptr, fileOffset, SEEK_SET ) != 0 )
	{
		printf ( "cipherBytes: Unable to set file pointer to %ld \n", fileOffset );
		fclose ( fptr );
		return;
	}
	nItems = fwrite ( buffer, sizeof ( BYTE ), nbytes, fptr );
	if ( nItems  <nbytes )
	{
		printf ( "cipherBytes: Trouble writing nItems = %d \n", nItems );
		fclose ( fptr );
		return;
	}

	printf ( "Successfully ciphered %d bytes\n", nbytes );
	fclose ( fptr );
	return;
}


/*
*	This function iterates over buffer, for the entirety of buffer_size, 
*	checking for the first byte of pattern. Then it checks for the entirety 
*	of pattern size until a match has been found
*/
int indexOf ( BYTE *buffer, size_t buffer_size, BYTE *pattern, size_t pattern_size ) {
	printf("\nBUFF BYTE %x:SIZE %d\nPTRN BYTE %x:SIZE %d\n", buffer, buffer_size, pattern, pattern_size);
	//	for (int i = 0; i < pattern_size; i++) {
	//		printf("%x", pattern[i]);
	//	}
	//	printf("\n\n");
	if ( pattern_size > buffer_size ) {
		printf ( "indexOf: pattern is bigger than buffer size\n" );
		return -1;
	}

	int j;
	int i;
	for ( i = 0; i < (int)(buffer_size - pattern_size); i++ ) {
		for ( j = 0; j < (int)(pattern_size - 1); j++ ) {
			if ( buffer[ i + j ] != pattern[ j ] ) {
				//the buffer location don't matchy match
				break;
			}
			printf ( "Matching byte %x at address %d\n", buffer[ i + j], &buffer[ i + j ] );
			printf ( "Value i: %d; Value j: %d\n", i, j );
			//printf ( "%x", buffer[ i + j ] );
			/*if ( j + 1 == pattern_size - 1 ) {
				printf ( "indexOf: pattern was found in buffer at offset %d\n", i );
				return i;
			}*/
				//plus 1 to account for 0 indexed arrays, subtract 1 to account for null byte
			if ( j+1 == pattern_size - 1 ) {
				printf ( "Pattern has been matched at buffer offset %d\n", i );
				return i;
			}
		}
	}
	printf ( "\nindexOf: no key found\n" );
	return -1;
}
/**
* Patch the filepath file (the .stub segment)
* Here we replace CODE_BASE_ADDRESS and CODE_SIZE by newBaseAddr and newSegSize
* newBaseAddr is the Virtual memory base address of .code segment in target file
* newSegSize contains the size of the target file .code segment
*/
int patchStub ( char * filepath, SEGMENT_INFO_PTR addrInfo, DWORD newBaseAddr, DWORD newSegSize )
{
	DWORD fileOffset;
	DWORD nbytes;
	DWORD nItems;
	/* Signature to locate where segment memory base address should be written */
	BYTE baseAddrSignature[ ] = { 0x15, 0x15, 0x15, 0x15, 0x00 };
	/* Signature to locate where segment size should be written*/
	BYTE segSizeSignature[ ] = { 0x14, 0x14, 0x14, 0x14, 0x00 };
	//BYTE * baseAddrAddress = NULL;
	int baseAddrAddress = NULL;
	int segSizeAddress = NULL;
	//BYTE * segSizeAddress = NULL;
	BYTE * buffer;
	FILE* fptr;
	fileOffset = addrInfo->fileSegmentOffset;
	nbytes = addrInfo->fileSegmentSize;

	/* Allocate memory in buffer that will store content of segment */

	buffer = ( BYTE* )malloc ( nbytes );
	if ( buffer == NULL )
	{
		printf ( "patchStub: malloc error \n" );
		return 1;
	}

	/* Open binary file */
	fptr = fopen ( filepath, "r+b" );
	if ( fptr == NULL )
	{
		printf ( "patchStub: fopen error \n" );
		return 1;
	}

	/* Seek .stub section using calculated offset*/
	if ( fseek ( fptr, addrInfo->fileSegmentOffset, SEEK_SET ) != 0 )
	{
		printf ( "patchStub: Unable to set file pointer to %ld \n", addrInfo->fileSegmentOffset );
		fclose ( fptr );
		return 1;
	}
	/* Copy content of stub segment into buffer */
	nItems = fread ( buffer, sizeof ( BYTE ), nbytes, fptr );
	if ( nItems  <nbytes )
	{
		printf ( "patchStub: Trouble reading nItems = %d \n", nItems );
		fclose ( fptr );
		return 1;
	}

	/* Search the baseAddress in buffer section */
	baseAddrAddress = indexOf ( buffer, nItems, baseAddrSignature, sizeof ( baseAddrSignature ) );
	/* Change base Address by calculated value */
	if ( baseAddrAddress == -1 ) {
		printf ( "patchStub: unable to find base addy. rip\n" );
		return 1;
	}
	printf ( "patchStub: writing new address" );
	printf ( "\nnew Base address: %02x\n", newBaseAddr );
	memcpy ( &buffer[ baseAddrAddress ], &newBaseAddr, sizeof ( newBaseAddr ) );
	

	/* Search for segment size in buffer */
	printf ( "\npatchStub: writing new seg size\n" );
	segSizeAddress = indexOf ( buffer, nItems, segSizeSignature, sizeof ( segSizeSignature ) );
	/* Change base Address by calculated value */
	if ( segSizeAddress == -1 ) {
		printf ( "patchStub: found no segSizeSignature. rip\n" );
		return 1;
	}
	printf ( "patchStub: writing new seg size\n" );
	printf ( "\nnew Seg size: %02x\n", newSegSize);
	memcpy ( &buffer[ segSizeAddress ], &newSegSize, sizeof ( newSegSize ) );
	

	printf ( "patchStub: now writing buffers to disk\n" );

	/* Replace current .stub section in file by patched one */
	if ( fseek ( fptr, fileOffset, SEEK_SET ) != 0 )
	{
		printf ( "patchStub: Unable to set file pointer to %ld \n", fileOffset );
		fclose ( fptr );
		return 1;
	}
	nItems = fwrite ( buffer, sizeof ( BYTE ), nbytes, fptr );
	if ( nItems  <nbytes )
	{
		printf ( "patchStub: Trouble writing nItems = %d \n", nItems );
		fclose ( fptr );
		return 1;
	}
	printf ( "\nSuccessfully patched file\n" );
	fclose ( fptr );

	return 0;
}


int main ( ) {
	HANDLE hFile;
	HANDLE hMapFile;
	LPVOID lpFileBase;
	int retval;
	char * file = { "loader.exe" };
	SEGMENT_INFO codeSegment;
	SEGMENT_INFO stubSegment;

	retval = BaseAddress ( file, &hFile, &hMapFile, &lpFileBase );
	if ( retval == false ) {
		return 1;
	}

	codeSegment.moduleBase = ( DWORD )NULL;
	codeSegment.memorySegmentOffset = ( DWORD )NULL;
	codeSegment.fileSegmentOffset = ( DWORD )NULL;
	codeSegment.fileSegmentSize = ( DWORD )NULL;
	stubSegment.moduleBase = ( DWORD )NULL;
	stubSegment.memorySegmentOffset = ( DWORD )NULL;
	stubSegment.fileSegmentOffset = ( DWORD )NULL;
	stubSegment.fileSegmentSize = ( DWORD )NULL;

	getSegmentsInfo ( lpFileBase, &codeSegment, &stubSegment );


	printf ( "\n\n=======================\n" );
	printf ( ".code segment information: \n" );
	printf ( "RAM image base		=0x%08X\n", codeSegment.moduleBase );
	printf ( "RAM segment offset	=0x%08X\n", codeSegment.memorySegmentOffset );
	printf ( "File offset of code =0x%08X\n", codeSegment.fileSegmentOffset );
	printf ( "File size of code	=0x%08X\n", codeSegment.fileSegmentSize );
	printf ( "\n=======================\n" );
	printf ( ".stub segment information: \n" );
	printf ( "RAM image base		=0x%08X\n", stubSegment.moduleBase );
	printf ( "RAM segment offset	=0x%08X\n", stubSegment.memorySegmentOffset );
	printf ( "File offset of code =0x%08X\n", stubSegment.fileSegmentOffset );
	printf ( "File size of code	=0x%08X\n", stubSegment.fileSegmentSize );

	UnmapViewOfFile ( lpFileBase );
	CloseHandle ( hMapFile );
	CloseHandle ( hFile );

	cipherBytes ( file, &codeSegment );
	printf ( "Cyphered file.\n" );
	
	retval = patchStub ( file, &stubSegment, codeSegment.moduleBase + codeSegment.memorySegmentOffset, codeSegment.fileSegmentSize );

	if ( retval ) {
		printf ( "Was unable to patch file :'(\n" );
	}
	else {
		printf ( "Patched file. enjoy :)\n" );
	}
	
	return 0;
}