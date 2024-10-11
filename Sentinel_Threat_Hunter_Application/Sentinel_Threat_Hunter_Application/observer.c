#include "pch.h"
#include "observer.h"

BOOL GetUserDirectory(WCHAR sUserDirectoryPath[]) {
	WCHAR sTempPath[MAX_PATH];

	if (!sUserDirectoryPath) {
		printf("\t[-] GetUserDirectory received invalid parameter(s)!\n");
		return FALSE;
	}

	if (!GetEnvironmentVariableW(ENV_VARIABLE, sTempPath, (DWORD)sizeof(sTempPath))) {
		printf("\t[-] GetEnvironmentVariableW failed with status: %d\n", GetLastError());
		return FALSE;
	}

	swprintf(sUserDirectoryPath, STRING_SIZE, L"C:%s", sTempPath);

	return TRUE;
}

static BOOL RealizeStaticAnalysis(WCHAR sYaraPath[], WCHAR sYaraRulePath[], WCHAR sUserDirectoryPath[], WCHAR sFileName[]) {
	BOOL bReturn = FALSE;
	WCHAR sCommandLine[BIG_STRING_SIZE] = { '\0' };
	WCHAR sStaticResult[BIG_STRING_SIZE] = { '\0' };
	WCHAR sStaticResultLowerCase[BIG_STRING_SIZE] = { '\0' };

	if (!sYaraPath || !sYaraRulePath || !sUserDirectoryPath || !sFileName) {
		printf("\t[-] RealizeStaticAnalysis received invalid parameter(s)!\n");
		return FALSE;
	}

	swprintf(sCommandLine, sizeof(sCommandLine), L"%s %s %s\\%s", sYaraPath, sYaraRulePath, sUserDirectoryPath, sFileName);

	FILE* fp = _wpopen(sCommandLine, L"r");
	if (!fp)
		return FALSE;


	while (fgetws(sStaticResult, sizeof(sStaticResult), fp) != NULL) {
		swprintf(sStaticResultLowerCase, sizeof(sStaticResultLowerCase), L"%s", sStaticResult);
		_wcslwr_s(sStaticResultLowerCase, sizeof(sStaticResultLowerCase) / sizeof(WCHAR));

		if (sStaticResult && (wcsstr(sStaticResultLowerCase, L"erro") == NULL || wcsstr(sStaticResultLowerCase, L"error") == NULL)) {
			bReturn = TRUE;
			break;
		}
	}

	_pclose(fp);

	return bReturn;
}

VOID DirectoryChangesAnalyzer(POBSERVERARGUMENTS* pThreadArguments) {
	WCHAR sRulesDirectory[BIG_STRING_SIZE];
	WCHAR sRulesPath[BIG_STRING_SIZE];
	HANDLE hUserDirectory = NULL;
	HANDLE hYaraRulesFolder = NULL;
	DWORD dwNumberOfBytesWritten = NULL;
	WIN32_FIND_DATAW pFileData;
	PFILE_NOTIFY_INFORMATION pNotifyInfo = NULL;


	hUserDirectory = CreateFileW((*pThreadArguments)->sUserDirectoryPath, USER_DESIRED_ACCESS, DESIRED_SHARE_MODE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (hUserDirectory == INVALID_HANDLE_VALUE) {
		printf("\t[-] CreateFileW failed with status: %d\n", GetLastError());
		return;
	}

	pNotifyInfo = (PFILE_NOTIFY_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, HEAP_BUFFER_SIZE);
	if (!pNotifyInfo) {
		printf("\t[-] HeapAlloc failed with status: %d\n", GetLastError());
		goto _EndOfFunction;
	}

	wprintf(L"[i] Listening to changes on Path: %s\n", (*pThreadArguments)->sUserDirectoryPath);

	printf("[i] Analyzer is Listening!\n");

	while ((*pThreadArguments)->bKeepRunning) {

		if (!(*pThreadArguments)->bShouldVerify)
			continue;

		if (!ReadDirectoryChangesW(hUserDirectory, pNotifyInfo, HEAP_BUFFER_SIZE, TRUE, DESIRED_NOTIFICATION_OPTIONS, &dwNumberOfBytesWritten, NULL, NULL)) {
			printf("\t[-] ReadDirectoryChangesW failed with status: %d\n", GetLastError());
			goto _LoopEnd;
		}

		if (pNotifyInfo->Action != FILE_ACTION_ADDED && pNotifyInfo->Action != FILE_ACTION_RENAMED_NEW_NAME && pNotifyInfo->Action != FILE_ACTION_MODIFIED)
			goto _LoopEnd;

		DWORD dwPosition = pNotifyInfo->FileNameLength / sizeof(WCHAR);
		pNotifyInfo->FileName[dwPosition] = '\0';

		swprintf(sRulesDirectory, sizeof(sRulesDirectory), L"%s\\*", (*pThreadArguments)->YaraRulePath);

		hYaraRulesFolder = FindFirstFileW(sRulesDirectory, &pFileData);
		if (hYaraRulesFolder == INVALID_HANDLE_VALUE) {
			printf("\t[-] FindFirstFileW failed with status: %d\n", GetLastError());
			goto _EndOfFunction;
		}

		do {
			if (wcsstr(pFileData.cFileName, L".yar") == NULL)
				continue;

			swprintf(sRulesPath, sizeof(sRulesPath), L"%s%s", (*pThreadArguments)->YaraRulePath, pFileData.cFileName);
			if (!RealizeStaticAnalysis((*pThreadArguments)->YaraPath, sRulesPath, (*pThreadArguments)->sUserDirectoryPath, pNotifyInfo->FileName))
				continue;

			
			swprintf(sRulesPath, sizeof(sRulesPath), L"%s\\%s", (*pThreadArguments)->sUserDirectoryPath, pNotifyInfo->FileName);

			if (!DeleteFileW(sRulesPath)) {
				wprintf(L"\t[---] THE PROGRAM WAS NOT ABLE TO DELETE %s FILE!\n", pNotifyInfo->FileName);
				break;
			}
				


			printf("\n\n\t*************************************************************\n");
			wprintf(L"\t\t[*] %s File Deleted Successfully!\n", pNotifyInfo->FileName);
			printf("\t*************************************************************\n");


			break;
		} while (FindNextFileW(hYaraRulesFolder, &pFileData));



	_LoopEnd:
		(*pThreadArguments)->bShouldVerify = FALSE;
	}


_EndOfFunction:
	printf("\t[i] Stopping Process I!\n");
	(*pThreadArguments)->bShouldVerify = FALSE;
	if (hUserDirectory)
		CloseHandle(hUserDirectory);

	if (hYaraRulesFolder)
		FindClose(hYaraRulesFolder);

	if (pNotifyInfo)
		HeapFree(GetProcessHeap(), 0, pNotifyInfo);
}

VOID DirectoryChangesObserver(POBSERVERARGUMENTS* pThreadArguments) {
	HANDLE hNotification = NULL;

	hNotification = FindFirstChangeNotificationW((*pThreadArguments)->sUserDirectoryPath, TRUE, DESIRED_NOTIFICATION_OPTIONS);
	if (hNotification == INVALID_HANDLE_VALUE) {
		printf("\t[-] FindFirstChangeNotificationW failed with status: %d\n", GetLastError());
		return;
	}

	printf("[i] Observer is Listening!\n");

	while ((*pThreadArguments)->bKeepRunning) {
		WaitForSingleObject(hNotification, INFINITE);

		(*pThreadArguments)->bShouldVerify = TRUE;

		while ((*pThreadArguments)->bShouldVerify)
			Sleep(1);

		FindNextChangeNotification(hNotification);
	}

	printf("\t[i] Stopping Process II!\n");

	if (hNotification)
		FindCloseChangeNotification(hNotification);
}