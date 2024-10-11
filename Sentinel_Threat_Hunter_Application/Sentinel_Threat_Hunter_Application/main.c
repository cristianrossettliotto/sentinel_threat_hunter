#include "pch.h"
#include "observer.h"
#include "injector.h"

int wmain(const int argc, const wchar_t* argv[]) {
	HANDLE hThreadAnalyzer = NULL;
	HANDLE hThreadObserver = NULL;
	HANDLE hProcessInjectorObserver = NULL;
	
	POBSERVERARGUMENTS pObserverArguments = NULL;


	if (argc < 3) {
		wprintf(L"[-] \"%s\" Usage: <PATH TO YARA EXECUTABLE> <PATH TO YARA RULES FOLDER>\n", argv[0]);
		return EXIT_FAILURE;
	}

	do {
		pObserverArguments = (POBSERVERARGUMENTS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)sizeof(OBSERVERARGUMENTS));
		if (!pObserverArguments) {
			printf("\t[-] HeapAlloc failed with status: %d\n", GetLastError());
			break;
		}

		if (!GetUserDirectory(pObserverArguments->sUserDirectoryPath)) {
			printf("[-] Failed!\n");
			break;
		}

		pObserverArguments->YaraPath = argv[1];
		pObserverArguments->YaraRulePath = argv[2];
		pObserverArguments->bKeepRunning = TRUE;
		pObserverArguments->bShouldVerify = FALSE;

		hThreadAnalyzer = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) DirectoryChangesAnalyzer, &pObserverArguments, 0, NULL);
		if (!hThreadAnalyzer) {
			printf("\t[-] CreateThread 1 failed with status: %d\n", GetLastError());
			break;
		}

		hThreadObserver = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) DirectoryChangesObserver, &pObserverArguments, 0, NULL);
		if (!hThreadObserver) {
			printf("\t[-] CreateThread 2 failed with status: %d\n", GetLastError());
			break;
		}

		hProcessInjectorObserver = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) ProcessCreationObserver, &(pObserverArguments->bKeepRunning), 0, NULL);
		if (!hThreadObserver) {
			printf("\t[-] CreateThread 3 failed with status: %d\n", GetLastError());
			break;
		}

		getch();
		getch();

		printf("Giving the Sign to Stop!\n");

		pObserverArguments->bKeepRunning = FALSE;
		pObserverArguments->bShouldVerify = FALSE;

		getch();

	} while (FALSE);

	if (pObserverArguments)
		HeapFree(GetProcessHeap(), 0, pObserverArguments);

	if (hThreadAnalyzer)
		CloseHandle(hThreadAnalyzer);

	if (hThreadObserver)
		CloseHandle(hThreadObserver);

	if (hProcessInjectorObserver)
		CloseHandle(hProcessInjectorObserver);

	return EXIT_SUCCESS;
}