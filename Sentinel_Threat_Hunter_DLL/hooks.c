#include "pch.h"
#include "hooks.h"

BOOL InitializeDetoursHooking() {
    DWORD dwDetoursRet = NULL;

    for (int i = 0; i < TECHNIQUES_BUFFER_SIZE; i++)
        Techniques[i] = NULL;

    DetourRestoreAfterWith();

    dwDetoursRet = DetourTransactionBegin();
    if (dwDetoursRet != NO_ERROR) {
        printf("\t\t[-] DetourTransactionBegin failed with error: %d \n", dwDetoursRet);
        return FALSE;
    }

    dwDetoursRet = DetourUpdateThread(GetCurrentThread());
    if (dwDetoursRet != NO_ERROR) {
        printf("\t\t[-] DetourUpdateThread failed with error: %d \n", dwDetoursRet);
        return FALSE;
    }

    dwDetoursRet = DetourAttach(&(PVOID)pWriteFile, HookedWriteFile);
    if (dwDetoursRet != NO_ERROR) {
        printf("\t\t[-] DetourAttach HookedWriteFile failed with error: %d \n", dwDetoursRet);
        return FALSE;
    }

    dwDetoursRet = DetourAttach(&(PVOID)pVirtualAllocEx, HookedVirtualAllocEx);
    if (dwDetoursRet != NO_ERROR) {
        printf("\t\t[-] DetourAttach HookedVirtualAllocEx failed with error: %d \n", dwDetoursRet);
        return FALSE;
    }

    dwDetoursRet = DetourAttach(&(PVOID)pVirtualProtectEx, HookedVirtualProtectEx);
    if (dwDetoursRet != NO_ERROR) {
        printf("\t\t[-] DetourAttach HookedVirtualProtectEx failed with error: %d \n", dwDetoursRet);
        return FALSE;
    }

    dwDetoursRet = DetourAttach(&(PVOID)pCreateRemoteThread, HookeCreateRemoteThread);
    if (dwDetoursRet != NO_ERROR) {
        printf("\t\t[-] DetourAttach HookeCreateRemoteThread failed with error: %d \n", dwDetoursRet);
        return FALSE;
    }

    dwDetoursRet = DetourAttach(&(PVOID)pSetThreadContext, HookedSetThreadContext);
    if (dwDetoursRet != NO_ERROR) {
        printf("\t\t[-] DetourAttach HookedSetThreadContext failed with error: %d \n", dwDetoursRet);
        return FALSE;
    }

    dwDetoursRet = DetourAttach(&(PVOID)pCreateFileA, HookedCreateFileA);
    if (dwDetoursRet != NO_ERROR) {
        printf("\t\t[-] DetourAttach HookedCreateFileA failed with error: %d \n", dwDetoursRet);
        return FALSE;
    }

    dwDetoursRet = DetourAttach(&(PVOID)pCreateFileMappingA, HookedCreateFileMappingA);
    if (dwDetoursRet != NO_ERROR) {
        printf("\t\t[-] DetourAttach HookedCreateFileMappingA failed with error: %d \n", dwDetoursRet);
        return FALSE;
    }

    dwDetoursRet = DetourAttach(&(PVOID)pMapViewOfFile, HookedMapViewOfFile);
    if (dwDetoursRet != NO_ERROR) {
        printf("\t\t[-] DetourAttach HookedMapViewOfFile failed with error: %d \n", dwDetoursRet);
        return FALSE;
    }

    dwDetoursRet = DetourTransactionCommit();
    if (dwDetoursRet != NO_ERROR) {
        printf("\t\t[-] DetourTransactionCommit failed with error: %d \n", dwDetoursRet);
        return FALSE;
    }

    printf("\t\t[+] Detour Attached Successfully!\n");
    return TRUE;
}

BOOL InitializeDetoursUnhooking() {
    DWORD dwDetoursRet = NULL;

    for (int i = 0; i < TECHNIQUES_BUFFER_SIZE; i++)
        if (Techniques[i])
            free(Techniques[i]);

    dwDetoursRet = DetourTransactionBegin();
    if (dwDetoursRet != NO_ERROR) {
        printf("\t\t[-] DetourTransactionBegin failed with error: %d \n", dwDetoursRet);
        return FALSE;
    }

    dwDetoursRet = DetourUpdateThread(GetCurrentThread());
    if (dwDetoursRet != NO_ERROR) {
        printf("\t\t[-] DetourUpdateThread failed with error: %d \n", dwDetoursRet);
        return FALSE;
    }

    dwDetoursRet = DetourDetach(&(PVOID)pWriteFile, HookedWriteFile);
    if (dwDetoursRet != NO_ERROR) {
        printf("\t\t[-] DetourDetach HookedWriteFile failed with error: %d \n", dwDetoursRet);
        return FALSE;
    }

    dwDetoursRet = DetourDetach(&(PVOID)pVirtualAllocEx, HookedVirtualAllocEx);
    if (dwDetoursRet != NO_ERROR) {
        printf("\t\t[-] DetourDetach HookedVirtualAllocEx failed with error: %d \n", dwDetoursRet);
        return FALSE;
    }

    dwDetoursRet = DetourDetach(&(PVOID)pVirtualProtectEx, HookedVirtualProtectEx);
    if (dwDetoursRet != NO_ERROR) {
        printf("\t\t[-] DetourDetach HookedVirtualProtectEx with error: %d \n", dwDetoursRet);
        return FALSE;
    }

    dwDetoursRet = DetourDetach(&(PVOID)pCreateRemoteThread, HookeCreateRemoteThread);
    if (dwDetoursRet != NO_ERROR) {
        printf("\t\t[-] DetourDetach HookeCreateRemoteThread with error: %d \n", dwDetoursRet);
        return FALSE;
    }

    dwDetoursRet = DetourDetach(&(PVOID)pSetThreadContext, HookedSetThreadContext);
    if (dwDetoursRet != NO_ERROR) {
        printf("\t\t[-] DetourDetach HookedSetThreadContext failed with error: %d \n", dwDetoursRet);
        return FALSE;
    }

    dwDetoursRet = DetourDetach(&(PVOID)pCreateFileA, HookedCreateFileA);
    if (dwDetoursRet != NO_ERROR) {
        printf("\t\t[-] DetourDetach HookedCreateFileA failed with error: %d \n", dwDetoursRet);
        return FALSE;
    }

    dwDetoursRet = DetourDetach(&(PVOID)pCreateFileMappingA, HookedCreateFileMappingA);
    if (dwDetoursRet != NO_ERROR) {
        printf("\t\t[-] DetourDetach HookedCreateFileMappingA failed with error: %d \n", dwDetoursRet);
        return FALSE;
    }

    dwDetoursRet = DetourDetach(&(PVOID)pMapViewOfFile, HookedMapViewOfFile);
    if (dwDetoursRet != NO_ERROR) {
        printf("\t\t[-] DetourDetach HookedMapViewOfFile failed with error: %d \n", dwDetoursRet);
        return FALSE;
    }

    dwDetoursRet = DetourTransactionCommit();
    if (dwDetoursRet != NO_ERROR) {
        printf("\t\t[-] DetourTransactionCommit failed with error: %d \n", dwDetoursRet);
        return FALSE;
    }

    return TRUE;
}

static BOOL HookedSetThreadContext(_In_ HANDLE hThread, _In_ CONST CONTEXT* lpContext) {
    BOOL bRet = FALSE;
    TECHNIQUEPERFORMING* Technique = NULL;

    __try {

#ifdef _M_X64
        if (FindTechniquePerformingByTargetAddress(&Technique, lpContext->Rip))
            SET_TECHNIQUE_FLAG(Technique->ucTechniquesFlags, TECHNIQUE_STEP_SET_THREAD_CONTEXT);
#endif

#ifdef _M_IX86
        if (FindTechniquePerformingByTargetAddress(&Technique, lpContext->Eip))
            SET_TECHNIQUE_FLAG(Technique->ucTechniquesFlags, TECHNIQUE_STEP_SET_THREAD_CONTEXT);
#endif

        if (Technique && (Technique->ucTechniquesFlags & TECHNIQUE_STEP_VIRTUAL_ALLOC_EX) && (Technique->ucTechniquesFlags & TECHNIQUE_STEP_VIRTUAL_PROTECT_EX) && (Technique->ucTechniquesFlags & TECHNIQUE_STEP_SET_THREAD_CONTEXT))
            TerminateCurrentProcess();

        bRet = pSetThreadContext(hThread, lpContext);
    }
    __finally {
        return bRet;
    }

}

static BOOL HookedWriteFile(_In_ HANDLE hFile, _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer, _In_ DWORD nNumberOfBytesToWrite, _Out_opt_ LPDWORD lpNumberOfBytesWritten, _Inout_opt_ LPOVERLAPPED lpOverlapped) {
    BOOL bRet = FALSE;
    DWORD dwCounter = 0;
    TECHNIQUEPERFORMING* Technique = NULL;

    for (int i = 0; i < nNumberOfBytesToWrite; i++)
        if ((((PBYTE)lpBuffer)[i] < 0x20 || ((PBYTE)lpBuffer)[i] > 0x7E))
            dwCounter++;

    __try {

        if (FindTechniquePerformingByStepPerformed(&Technique, TECHNIQUE_STEP_ENCRYPTION)) {
            Technique->dwCounter = (dwCounter >= INVALID_CHARACTER_THRESHOLD) ? Technique->dwCounter + 1 : Technique->dwCounter;
            Technique->hTarget = hFile;
        }


        if (!Technique && GetNewTechniquePerforming(&Technique)) {
            Technique->dwCounter = (dwCounter >= INVALID_CHARACTER_THRESHOLD) ? 1 : 0;
            Technique->hTarget = hFile;
            Technique->ucTechniquesFlags = 0x0;
            SET_TECHNIQUE_FLAG(Technique->ucTechniquesFlags, TECHNIQUE_STEP_ENCRYPTION);
        }


        if (Technique->dwCounter >= ENCRYPTION_THRESHOLD)
            TerminateCurrentProcess();


        bRet = pWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    }
    __finally {
        return bRet;
    }
}

static LPVOID HookedVirtualAllocEx(_In_ HANDLE hProcess, _In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect) {
    if (flProtect == PAGE_EXECUTE_READWRITE)
        TerminateCurrentProcess();

    TECHNIQUEPERFORMING* Technique = NULL;

    LPVOID lpAddressReturned = pVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);

    __try {
        if (GetNewTechniquePerforming(&Technique)) {
            Technique->dwCurrentProtection = flProtect;
            Technique->lpAddressTarget = lpAddressReturned;
            Technique->ucTechniquesFlags = 0x0;
            SET_TECHNIQUE_FLAG(Technique->ucTechniquesFlags, TECHNIQUE_STEP_VIRTUAL_ALLOC_EX);
        }

        if (!Technique)
            return NULL;
    }
    __finally {
        return lpAddressReturned;
    }
}

static BOOL HookedVirtualProtectEx(_In_ HANDLE hProcess, _In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect) {
    BOOL bRet = FALSE;
    TECHNIQUEPERFORMING* Technique = NULL;

    __try {

        if (flNewProtect == PAGE_EXECUTE_READWRITE)
            TerminateCurrentProcess();

        bRet = pVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);

        if (FindTechniquePerformingByTargetAddress(&Technique, lpAddress)) {
            

            if (Technique->dwCurrentProtection == PAGE_READWRITE && flNewProtect == PAGE_EXECUTE_READ)
                TerminateCurrentProcess();

            Technique->dwCurrentProtection = flNewProtect;
            SET_TECHNIQUE_FLAG(Technique->ucTechniquesFlags, TECHNIQUE_STEP_VIRTUAL_PROTECT_EX);


        }
    }
    __finally {
        return bRet;
    }
}

static HANDLE HookeCreateRemoteThread(_In_ HANDLE hProcess, _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes, _In_ SIZE_T dwStackSize, _In_ LPTHREAD_START_ROUTINE lpStartAddress, _In_opt_ LPVOID lpParameter, _In_ DWORD dwCreationFlags, _Out_opt_ LPDWORD lpThreadId) {
    HANDLE hRemoteThread = NULL;
    TECHNIQUEPERFORMING* Technique = NULL;

    __try {
        if (FindTechniquePerformingByTargetAddress(&Technique, lpStartAddress))
            SET_TECHNIQUE_FLAG(Technique->ucTechniquesFlags, TECHNIQUE_STEP_CREATE_REMOTE_THREAD);


        if (Technique && (Technique->ucTechniquesFlags & TECHNIQUE_STEP_VIRTUAL_ALLOC_EX) && (Technique->ucTechniquesFlags & TECHNIQUE_STEP_VIRTUAL_PROTECT_EX) && (Technique->ucTechniquesFlags & TECHNIQUE_STEP_CREATE_REMOTE_THREAD))
            TerminateCurrentProcess();

        hRemoteThread = CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    }
    __finally {
        return hRemoteThread;
    }
}

static HANDLE HookedCreateFileA(_In_ LPCSTR lpFileName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwShareMode, _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes, _In_ DWORD dwCreationDisposition, _In_ DWORD dwFlagsAndAttributes, _In_opt_ HANDLE hTemplateFile) {
    HANDLE hFileHandle = NULL;
    UCHAR sLowerCaseFileName[1024 * 2];
    TECHNIQUEPERFORMING* Technique = NULL;

    hFileHandle = pCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

    __try {
        sprintf_s(sLowerCaseFileName, sizeof(sLowerCaseFileName), "%s", lpFileName);
        _strlwr_s(sLowerCaseFileName, sizeof(sLowerCaseFileName));

        printf("[.] File Lower Case Name: %s\n", sLowerCaseFileName);

        if ((strstr(sLowerCaseFileName, "kernel32.dll") || strstr(sLowerCaseFileName, "ntdll.dll")) && GetNewTechniquePerforming(&Technique)) {
            Technique->hTarget = hFileHandle;
            Technique->ucTechniquesFlags = 0x0;
            SET_TECHNIQUE_FLAG(Technique->ucTechniquesFlags, TECHNIQUE_STEP_EDR_EVADING_CREATE_FILE);
        }
    }
    __finally {
        return hFileHandle;
    }
}

static HANDLE HookedCreateFileMappingA(_In_ HANDLE hFile, _In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes, _In_ DWORD flProtect, _In_ DWORD dwMaximumSizeHigh, _In_ DWORD dwMaximumSizeLow, _In_opt_ LPCSTR lpName) {
    HANDLE hMapFile = NULL;
    TECHNIQUEPERFORMING* Technique = NULL;

    __try {
        hMapFile = pCreateFileMappingA(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);

        if (!FindTechniquePerformingByStepPerformed(&Technique, TECHNIQUE_STEP_EDR_EVADING_CREATE_FILE))
            return NULL;

        if (Technique->hTarget == hFile) {
            Technique->hTarget = hMapFile;
            SET_TECHNIQUE_FLAG(Technique->ucTechniquesFlags, TECHNIQUE_STEP_EDR_EVADING_FILE_MAP);
        }
    }
    __finally {
        return hMapFile;
    }
}

static LPVOID HookedMapViewOfFile(_In_ HANDLE hFileMappingObject, _In_ DWORD dwDesiredAccess, _In_ DWORD dwFileOffsetHigh, _In_ DWORD dwFileOffsetLow, _In_ SIZE_T dwNumberOfBytesToMap) {
    LPVOID pMapView = NULL;
    TECHNIQUEPERFORMING* Technique = NULL;

    __try {
        if (!FindTechniquePerformingByStepPerformed(&Technique, TECHNIQUE_STEP_EDR_EVADING_FILE_MAP) || !FindTechniquePerformingByStepPerformed(&Technique, TECHNIQUE_STEP_EDR_EVADING_CREATE_FILE))
            return NULL;

        SET_TECHNIQUE_FLAG(Technique->ucTechniquesFlags, TECHNIQUE_STEP_EDR_EVADING_MAP_VIEW);


        if (Technique->hTarget == hFileMappingObject)
            TerminateCurrentProcess();

        if (Technique && (Technique->ucTechniquesFlags & TECHNIQUE_STEP_EDR_EVADING_CREATE_FILE) && (Technique->ucTechniquesFlags & TECHNIQUE_STEP_EDR_EVADING_FILE_MAP) && (Technique->ucTechniquesFlags & TECHNIQUE_STEP_EDR_EVADING_MAP_VIEW))
            TerminateCurrentProcess();

        pMapView = pMapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
    }
    __finally {
        return pMapView;
    }
}