#include <stdio.h>
#include <Windows.h>


#define DLL_PATH_X86 L"C:\\Program Files\\SentinelThreatHunter\\x86\\Sentinel_Threat_Hunter_DLL.dll"

int main(const int argc, const char* argv[]) {
	if (argc < 2)
		return EXIT_FAILURE;

	PVOID pMemPage = NULL;
	HANDLE hProcess = NULL;
	LPVOID pProcedure = NULL;
	DWORD dwThreadId = NULL;
	SIZE_T stDllPathSize = NULL;
	SIZE_T stBytesWritten = NULL;
	DWORD dwProcessId = (DWORD)atoi(argv[1]);

	do {
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)dwProcessId);
		if (!hProcess) {
			printf("\t[-] OpenProcess Process ID: %d failed with status: %d\n", dwProcessId, GetLastError());
			break;
		}

		stDllPathSize = sizeof(DLL_PATH_X86);

		pMemPage = VirtualAllocEx(hProcess, NULL, stDllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!pMemPage) {
			printf("\t[-] VirtualAllocEx Process ID: %d failed with status: %d\n", dwProcessId, GetLastError());
			break;
		}

		if (!WriteProcessMemory(hProcess, pMemPage, DLL_PATH_X86, stDllPathSize, &stBytesWritten) || stBytesWritten != stDllPathSize) {
			printf("\t[-] WriteProcessMemory Process ID: %d failed with status: %d\n", dwProcessId, GetLastError());
			break;
		}

		pProcedure = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
		if (!pProcedure) {
			printf("\t[-] GetProcAddress/GetModuleHandleW Process ID: %d failed with status: %d\n", dwProcessId, GetLastError());
			break;
		}

		CreateRemoteThread(hProcess, NULL, NULL, pProcedure, pMemPage, 0, &dwThreadId);
	} while (FALSE);


	if (hProcess)
		CloseHandle(hProcess);

	return EXIT_SUCCESS;
}