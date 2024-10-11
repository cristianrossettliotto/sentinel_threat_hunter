#pragma once

#include <ntifs.h>
#include <wdm.h>
#include <ntstrsafe.h>


typedef struct {
	ULONG ProcessId;
	ULONG ThreadId;
} ProcessInfo;