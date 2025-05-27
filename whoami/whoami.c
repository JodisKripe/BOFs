#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <lmcons.h>
#include "beacon.h"

#define WINBOOL BOOL

WINBASEAPI WINBOOL WINAPI KERNEL32$GetComputerNameA (LPSTR lpBuffer, LPDWORD nSize);
#define GetComputerNameA KERNEL32$GetComputerNameA

WINADVAPI WINBOOL WINAPI ADVAPI32$GetUserNameA (LPSTR lpBuffer, LPDWORD pcbBuffer);
#define GetUserNameA ADVAPI32$GetUserNameA

WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (VOID);
#define GetLastError KERNEL32$GetLastError

// x86_64-w64-mingw32-gcc -c whoami.c -o whoami.o

void go(void * args, int len) {
    char username[UNLEN + 1]; // Buffer for username
    DWORD username_len = UNLEN + 1; // Initial buffer size for username
    if (GetUserNameA(username, &username_len)) {
        BeaconPrintf(CALLBACK_OUTPUT, "Current User: %s\n", username);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get current user name.\n",GetLastError());
    }

    char computername[MAX_COMPUTERNAME_LENGTH + 1]; // Buffer for computer name
    DWORD computername_len = MAX_COMPUTERNAME_LENGTH + 1; // Initial buffer size for computer name
    if (GetComputerNameA(computername, &computername_len)) {
        BeaconPrintf(CALLBACK_OUTPUT, "Computer Name: %s\n", computername);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get computer name.\n", GetLastError());
    }

    BeaconPrintf(CALLBACK_OUTPUT, "User Context: %s\\%s\n", computername, username);
}