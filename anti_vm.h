#pragma once
#include <windows.h>
#include <tchar.h>
#include <Winternl.h>
#include <devguid.h>    // Device guids
#include <winioctl.h>	// IOCTL
#include <intrin.h>		// cpuid()

#include <powrprof.h>	// check_power_modes()
#pragma comment(lib, "powrprof.lib")


#include <SetupAPI.h>
#pragma comment(lib, "setupapi.lib")



/*
Check if there is any mouse movement in the sandbox.
*/
BOOL mouse_movement ( ) {

	POINT positionA = { };
	POINT positionB = { };

	/* Retrieve the position of the mouse cursor, in screen coordinates */
	GetCursorPos ( &positionA );

	/* Wait a moment */
	Sleep ( 5000 );

	/* Retrieve the poition gain */
	GetCursorPos ( &positionB );

	if ( ( positionA.x == positionB.x ) && ( positionA.y == positionB.y ) )
		/* Probably a sandbox, because mouse position did not change. */
		return TRUE;

	else
		return FALSE;
}

/*
Check if the machine have enough memory space, usually VM get a small ammount,
one reason if because several VMs are running on the same servers so they can run
more tasks at the same time.
*/
BOOL memory_space ( )
{
	DWORDLONG ullMinRam = ( 1024LL * ( 1024LL * ( 1024LL * 1LL ) ) ); // 1GB
	MEMORYSTATUSEX statex = { 0 };

	statex.dwLength = sizeof ( statex );
	GlobalMemoryStatusEx ( &statex );

	return ( statex.ullTotalPhys < ullMinRam ) ? TRUE : FALSE;
}

/*
This trick consists of getting information about total amount of space.
This can be used to expose a sandbox.
*/
BOOL disk_size_getdiskfreespace ( )
{
	ULONGLONG minHardDiskSize = ( 80ULL * ( 1024ULL * ( 1024ULL * ( 1024ULL ) ) ) );
	LPCWSTR pszDrive = NULL;
	BOOL bStatus = FALSE;

	// 64 bits integer, low and high bytes
	ULARGE_INTEGER totalNumberOfBytes;

	// If the function succeeds, the return value is nonzero. If the function fails, the return value is 0 (zero).
	bStatus = GetDiskFreeSpaceEx ( pszDrive, NULL, &totalNumberOfBytes, NULL );
	if ( bStatus ) {
		if ( totalNumberOfBytes.QuadPart < minHardDiskSize )  // 80GB
			return TRUE;
	}

	return FALSE;;
}

/*
Sleep and check if time have been accelerated
*/
BOOL accelerated_sleep ( )
{
	DWORD dwStart = 0, dwEnd = 0, dwDiff = 0;
	DWORD dwMillisecondsToSleep = 60 * 1000;

	/* Retrieves the number of milliseconds that have elapsed since the system was started */
	dwStart = GetTickCount ( );

	/* Let's sleep 1 minute so Sandbox is interested to patch that */
	Sleep ( dwMillisecondsToSleep );

	/* Do it again */
	dwEnd = GetTickCount ( );

	/* If the Sleep function was patched*/
	dwDiff = dwEnd - dwStart;
	if ( dwDiff > dwMillisecondsToSleep - 1000 ) // substracted 1s just to be sure
		return FALSE;
	else
		return TRUE;
}

/*
The CPUID instruction is a processor supplementary instruction (its name derived from
CPU IDentification) for the x86 architecture allowing software to discover details of
the processor. By calling CPUID with EAX =1, The 31bit of ECX register if set will
reveal the precense of a hypervisor.
*/
BOOL cpuid_is_hypervisor ( )
{
	INT CPUInfo[ 4 ] = { -1 };

	/* Query hypervisor precense using CPUID (EAX=1), BIT 31 in ECX */
	__cpuid ( CPUInfo, 1 );
	if ( ( CPUInfo[ 2 ] >> 31 ) & 1 )
		return TRUE;
	else
		return FALSE;
}

int antivm ( ) {
	return 1;
	if (
		cpuid_is_hypervisor ( ) ||
		accelerated_sleep ( ) ||
		disk_size_getdiskfreespace ( ) ||
		memory_space ( ) ) {
		return 0;
	}
	return 1;
}