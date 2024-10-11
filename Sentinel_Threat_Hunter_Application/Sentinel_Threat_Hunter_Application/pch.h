#pragma once

#include <stdio.h>
#include <string.h>
#include <Windows.h>

#define DEVICE_SENTINEL 0x8035
#define EVENT_NAME L"Global\\SentinelProcessCreation"
#define DLL_X86_INJECTOR L"C:\\Program Files\\SentinelThreatHunter\\Sentinel_Threat_Hunter_AppInjector.exe"
#define DLL_PATH_X64 L"C:\\Program Files\\SentinelThreatHunter\\x64\\Sentinel_Threat_Hunter_DLL.dll"
#define IOTCTL_SENTINEL_GET_ID CTL_CODE(DEVICE_SENTINEL, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)


#define ENV_VARIABLE L"HOMEPATH"
#define USER_DESIRED_ACCESS GENERIC_READ | GENERIC_WRITE
#define DESIRED_SHARE_MODE FILE_SHARE_READ | FILE_SHARE_WRITE
#define DESIRED_NOTIFICATION_OPTIONS FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_SECURITY

#define STRING_SIZE (MAX_PATH * 2)
#define BIG_STRING_SIZE (STRING_SIZE * 10)
#define HEAP_BUFFER_SIZE ( sizeof(FILE_NOTIFY_INFORMATION) + STRING_SIZE * sizeof(WCHAR))

typedef struct {
	WCHAR* YaraPath;
	WCHAR* YaraRulePath;
	WCHAR sUserDirectoryPath[STRING_SIZE];
	BOOL bKeepRunning;
	BOOL bShouldVerify;
} OBSERVERARGUMENTS, * POBSERVERARGUMENTS;

typedef struct {
	ULONG ProcessId;
	ULONG ThreadId;
} ProcessInfo;