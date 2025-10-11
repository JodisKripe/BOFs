#include <windows.h>
#include <stdio.h>
#include <sddl.h>
#include <stdlib.h>
#include <malloc.h>
#include <lmcons.h>
#include "beacon.h"

#define WINBOOL BOOL
#define HANDLE void*

// cd /usr/share/mingw-w64/x86_64-w64-mingw32/include && grep -r " GetCurrentProcess" etc
// x86_64-w64-mingw32-gcc -c tokenInfo.c -o tokenInfo.o 

WINADVAPI WINBOOL WINAPI ADVAPI32$LookupPrivilegeNameA (LPCSTR lpSystemName, PLUID lpLuid, LPSTR lpName, LPDWORD cchName);
#define LookupPrivilegeNameA ADVAPI32$LookupPrivilegeNameA

WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
#define GetProcessHeap KERNEL32$GetProcessHeap

WINBASEAPI void * WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
#define HeapAlloc KERNEL32$HeapAlloc

WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess (VOID);
#define GetCurrentProcess KERNEL32$GetCurrentProcess

WINADVAPI WINBOOL WINAPI ADVAPI32$OpenProcessToken (HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
#define OpenProcessToken ADVAPI32$OpenProcessToken

WINADVAPI WINBOOL WINAPI ADVAPI32$GetTokenInformation (HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
#define GetTokenInformation ADVAPI32$GetTokenInformation

WINADVAPI WINBOOL WINAPI ADVAPI32$ConvertSidToStringSidA (PSID Sid, LPSTR* StringSid);
#define ConvertSidToStringSidA ADVAPI32$ConvertSidToStringSidA

WINADVAPI WINBOOL WINAPI ADVAPI32$GetUserNameA (LPSTR lpBuffer, LPDWORD pcbBuffer);
#define GetUserNameA ADVAPI32$GetUserNameA

WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (VOID);
#define GetLastError KERNEL32$GetLastError

WINADVAPI WINBOOL WINAPI ADVAPI32$LookupAccountSidA (LPCSTR lpSystemName, PSID Sid, LPSTR Name, LPDWORD cchName, LPSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
#define LookupAccountSidA ADVAPI32$LookupAccountSidA

// WINBASEAPI WINBOOL WINAPI KERNEL32$GetComputerNameA (LPSTR lpBuffer, LPDWORD nSize);
// #define GetComputerNameA KERNEL32$GetComputerNameA

#define _DEBUG 1 // Set to 1 to enable debug output, 0 for production use
// x86_64-w64-mingw32-gcc -c tokenInfo.c -o tokenInfo.o

void groups(HANDLE tokenH){
	DWORD ulen = 25000;
	VOID* buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ulen);
	GetTokenInformation(tokenH, TokenGroups, (LPVOID)buffer, ulen, &ulen);
	PTOKEN_GROUPS pGroupInfo = (PTOKEN_GROUPS)buffer;
	if (pGroupInfo == NULL) {
	BeaconPrintf(CALLBACK_OUTPUT, "Group Information could not be fetched.\n0x%p", GetLastError());
		return ;
	}
	else {
		BeaconPrintf(CALLBACK_OUTPUT, "The total Groups Privileges of the current process are: %d\n\n", pGroupInfo->GroupCount);
	}

	// #if !_DEBUG
	// BeaconPrintf(CALLBACK_OUTPUT, "Unique Groups:\n");
	// #endif
	char* allGroups = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,16384);
	for (int index = 0;index < pGroupInfo->GroupCount;index++) {
		char GroupName[1024] = { 0 };
		char DomainName[1024] = { 0 };
		PSID psid;
		char* sidString = NULL;
		DWORD groupsize ;
		DWORD domainsize ;
		SID_NAME_USE sidtype;
		SID sid;
		
		psid = pGroupInfo->Groups[index].Sid;
		LookupAccountSidA(NULL,psid, GroupName, &groupsize, DomainName, &domainsize, &sidtype);
		ConvertSidToStringSidA(psid, &sidString);
		#if _DEBUG
		BeaconPrintf(CALLBACK_OUTPUT,"psid: 0x%p\nGroupName: %s\ngroupsize: %d\nDomainName: %s\ndomainsize: %d\nSID String: %s\n\n", psid, GroupName, groupsize, DomainName, domainsize, sidString);
		#endif
	}
}

void UserInfo(HANDLE tokenH){
	// Token User
	char* pSidStr = NULL;
	char uname[256];
	DWORD szUname = 256;

	VOID* buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1000);
	DWORD ulen = 1000;

	GetUserNameA(uname, &szUname);
	
	GetTokenInformation(tokenH,TokenUser, (LPVOID)buffer, ulen, &ulen);
	
	PTOKEN_USER pUserInfo = (PTOKEN_USER)buffer;
	#if _DEBUG
	BeaconPrintf(CALLBACK_OUTPUT,"Token information size: %d\nSID Pointer: 0x%p\n", ulen, pUserInfo);
	#endif
	if (pUserInfo == NULL) {
		BeaconPrintf(CALLBACK_OUTPUT,"User information could not be obtained.");
		return;
	}
	else {
		ConvertSidToStringSidA(pUserInfo->User.Sid, &pSidStr);
		BeaconPrintf(CALLBACK_OUTPUT,"Username:%s \nSID of the user: %s\n\n",uname,pSidStr);
	}
}

void privileges(HANDLE tokenH){
	DWORD ulen = 20000;
	VOID* buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ulen);
	GetTokenInformation(tokenH, TokenPrivileges, (LPVOID)buffer, ulen, &ulen);
	PTOKEN_PRIVILEGES pPrivInfo = (PTOKEN_PRIVILEGES)buffer;
	if (pPrivInfo == NULL) {
		BeaconPrintf(CALLBACK_OUTPUT,"Privilege Information could not be fetched.\n0x%p", GetLastError());
		return;
	}
	else {
		BeaconPrintf(CALLBACK_OUTPUT,"The total Privileges of the current process are: %d\n\n", pPrivInfo->PrivilegeCount);
	}

	#if !_DEBUG
	BeaconPrintf(CALLBACK_OUTPUT,"Unique Privileges:\n");
	#endif
	for (int index = 0;index < pPrivInfo->PrivilegeCount;index++) {
		char privName[1024] = { 0 };
		DWORD privsize = 1024;
		LUID luid = pPrivInfo->Privileges[index].Luid;
		BOOL attr = pPrivInfo->Privileges[index].Attributes;
		LookupPrivilegeNameA(NULL, &luid, privName, &privsize);
		if (privName[0] != '\0') {
			#if _DEBUG
			BeaconPrintf(CALLBACK_OUTPUT,"LUID: %lu\nAttributes: 0x%p\nPrivilege Name: %s\n\n", luid.LowPart, attr, privName);
			#else
			BeaconPrintf(CALLBACK_OUTPUT,"%s\n", privName);
			#endif
		}
}
}

void go(void * args, int len) {
	HANDLE pHandle = NULL;
	HANDLE tokenH = NULL;

	BOOL prog = FALSE;

	
	DWORD ulen = 1000;
	VOID* buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ulen);
	pHandle = GetCurrentProcess(); // 0xffffffff due to the way GetCurrentProcess works, it returns a pseudo handle that is always valid for the current process.
	if (pHandle == NULL) {
		BeaconPrintf(CALLBACK_OUTPUT,"Handle to the current process' token could not be obtained.\n 0x%p\n", GetLastError());
		return;
	}
	#if _DEBUG
	BeaconPrintf(CALLBACK_OUTPUT,"Handle to the current process' token: 0x%p\n", pHandle);
	#endif

	OpenProcessToken(pHandle, TOKEN_READ, &tokenH);
	if (tokenH == NULL) {
		BeaconPrintf(CALLBACK_OUTPUT,"Token handle could not be obtained.\n 0x%p\n", GetLastError());
		return;
	}
	#if _DEBUG
	BeaconPrintf(CALLBACK_OUTPUT,"Token handle: 0x%p\n", tokenH);
	#endif
	
	UserInfo(tokenH);
	groups(tokenH);
	privileges(tokenH);
	

}