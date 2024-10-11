#include "pch.h"
#include "injector.h"


VOID ProcessInjector(ProcessInfo * pProcessInfo) {
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	PVOID pMemPage = NULL;
	SIZE_T stDllPathSize = NULL;
	SIZE_T stBytesWritten = NULL;
	LPVOID pProcedure = NULL;
	BOOL bIsProcess32 = FALSE;
	DWORD dwThreadId = NULL;

	do {

		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pProcessInfo->ProcessId);
		if (!hProcess) {
			printf("\t[-] OpenProcess Process ID: %d failed with status: %d\n", pProcessInfo->ProcessId, GetLastError());
			break;
		}


		if (!IsWow64Process(hProcess, &bIsProcess32)) {
			printf("\t[-] IsWow64Process Process ID: %d failed with status: %d\n", pProcessInfo->ProcessId, GetLastError());
			break;
		}


		if (bIsProcess32) {
			STARTUPINFO sStartUp;
			PROCESS_INFORMATION lProcInfo;
			WCHAR sCommandLine[STRING_SIZE];
			
			RtlSecureZeroMemory(&sStartUp, sizeof(STARTUPINFO));
			RtlSecureZeroMemory(&lProcInfo, sizeof(PROCESS_INFORMATION));

			swprintf(sCommandLine, sizeof(sCommandLine), L"%s %d", DLL_X86_INJECTOR, pProcessInfo->ProcessId);

			sStartUp.cb = sizeof(STARTUPINFO);
			if(!CreateProcessW(NULL, sCommandLine, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, NULL, &sStartUp, &lProcInfo)) {
				printf("\t[-] CreateProcessW Process ID: %d failed with status: %d\n", pProcessInfo->ProcessId, GetLastError());
				break;
			}

			if (lProcInfo.hProcess)
				CloseHandle(lProcInfo.hProcess);

			if (lProcInfo.hThread)
				CloseHandle(lProcInfo.hThread);

			break;
		}

		stDllPathSize = sizeof(DLL_PATH_X64);

		pMemPage = VirtualAllocEx(hProcess, NULL, stDllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!pMemPage) {
			printf("\t[-] VirtualAllocEx Process ID: %d failed with status: %d\n", pProcessInfo->ProcessId, GetLastError());
			break;
		}

		if (!WriteProcessMemory(hProcess, pMemPage, DLL_PATH_X64, stDllPathSize, &stBytesWritten) || stBytesWritten != stDllPathSize) {
			printf("\t[-] WriteProcessMemory Process ID: %d failed with status: %d\n", pProcessInfo->ProcessId, GetLastError());
			break;
		}

		pProcedure = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
		if (!pProcedure) {
			printf("\t[-] GetProcAddress/GetModuleHandleW Process ID: %d failed with status: %d\n", pProcessInfo->ProcessId, GetLastError());
			break;
		}

		CreateRemoteThread(hProcess, NULL, NULL, pProcedure, pMemPage, 0, &dwThreadId);
	} while (FALSE);


	if (hProcess)
		CloseHandle(hProcess);

	if (hThread)
		CloseHandle(hThread);
}


VOID ProcessCreationObserver(BOOL* bKeepRunnning) {
	HANDLE hEvent = NULL;
	ProcessInfo pProcessInfo;
	DWORD dwResponseSizeInBytes = NULL;
	HANDLE hSentinelDriver = NULL;


	do {
		hSentinelDriver = CreateFileW(L"\\\\.\\SentinelThreatHunter", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (!hSentinelDriver) {
			printf("\t[-] CreateFileW to Driver failed with status: %d\n", GetLastError());
			break;
		}

		hEvent = OpenEventW(SYNCHRONIZE, FALSE, EVENT_NAME);
		if (!hEvent) {
			printf("[-] OpenEventW failed with status: %d\n", GetLastError());
			break;
		}


		printf("[i] Injector is Listening!\n");

		while ((*bKeepRunnning)) {
			WaitForSingleObject(hEvent, INFINITE);
			
			if (!DeviceIoControl(hSentinelDriver, IOTCTL_SENTINEL_GET_ID, NULL, 0, &pProcessInfo, sizeof(ProcessInfo), &dwResponseSizeInBytes, NULL)) {
				printf("[-] DeviceIoControl failed with status: %d\n", GetLastError());
				break;
			}

			CreateThread(NULL, NULL, ProcessInjector, &pProcessInfo, 0, NULL);
		}

	} while (FALSE);

	printf("\t[i] Stopping Process III!\n");
	*bKeepRunnning = FALSE;

	if (hEvent)
		CloseHandle(hEvent);

	if (hSentinelDriver)
		CloseHandle(hSentinelDriver);

}