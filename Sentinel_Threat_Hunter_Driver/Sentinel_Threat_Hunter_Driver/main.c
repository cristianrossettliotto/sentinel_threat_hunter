#include "pch.h"


#define DEVICE_SENTINEL 0x8035
#define EVENT_NAME L"\\BaseNamedObjects\\SentinelProcessCreation"
#define DLL_PATH L"C:\\Program Files\\SentinelThreatHunter\\Sentinel_Threat_Hunter_DLL.dll"
#define IOTCTL_SENTINEL_GET_ID CTL_CODE(DEVICE_SENTINEL, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

VOID SentinelUnload(PDRIVER_OBJECT pDriverObject);
VOID ProcessNotify(_Inout_ PEPROCESS pProcess, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO pCreateInfo);

DRIVER_DISPATCH SentinelCreateClose, SentinelDeviceControl;
UNICODE_STRING g_SymbolicName = RTL_CONSTANT_STRING(L"\\??\\SentinelThreatHunter");

HANDLE g_EventHandle = NULL;
PKEVENT g_pEvent = NULL;
ProcessInfo sProcessInfo = {.ProcessId = 0, .ThreadId = 0};

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT pDriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	UNICODE_STRING sEventName;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PDEVICE_OBJECT pDeviceObject = NULL;
	UNICODE_STRING sDeviceName = RTL_CONSTANT_STRING(L"\\Device\\SentinelThreatHunter");


	pDriverObject->DriverUnload = SentinelUnload;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SentinelDeviceControl;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = pDriverObject->MajorFunction[IRP_MJ_CLOSE] = SentinelCreateClose;

	do {
		ntStatus = IoCreateDevice(pDriverObject, 0, &sDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);
		if (!NT_SUCCESS(ntStatus)) {
			KdPrint(("Sentinel failed to Create Device (0x%08x)\n", ntStatus));
			break;
		}

		pDeviceObject->Flags |= DO_DIRECT_IO;

		ntStatus = IoCreateSymbolicLink(&g_SymbolicName, &sDeviceName);
		if (!NT_SUCCESS(ntStatus)) {
			KdPrint(("Sentinel failed to Create Symbolic Link (0x%08x)\n", ntStatus));
			break;
		}

		ntStatus = PsSetCreateProcessNotifyRoutineEx(ProcessNotify, FALSE);
		if (!NT_SUCCESS(ntStatus)) {
			KdPrint(("Sentinel failed to Create Process Notify Routine (0x%08x)\n", ntStatus));
			break;
		}

		RtlInitUnicodeString(&sEventName, EVENT_NAME);
		g_pEvent = IoCreateNotificationEvent(&sEventName, &g_EventHandle);
		if (g_pEvent == NULL) {
			KdPrint(("Sentinel failed to Create Named Event (0x%08x)\n", ntStatus));
			ntStatus = STATUS_UNSUCCESSFUL;
			break;
		}

		KdPrint(("Sentinel Current IRQL in Driver Entry: (0x%02x)\n", KeGetCurrentIrql()));
		ObReferenceObject(g_pEvent);
		
		KeClearEvent(g_pEvent);
	} while (FALSE);

	if (NT_SUCCESS(ntStatus))
		return ntStatus;

	SentinelUnload(pDriverObject);

	return ntStatus;
}

VOID SentinelUnload(PDRIVER_OBJECT pDriverObject) {
	IoDeleteSymbolicLink(&g_SymbolicName);
	IoDeleteDevice(pDriverObject->DeviceObject);
	PsSetCreateProcessNotifyRoutineEx(ProcessNotify, TRUE);

	if (g_EventHandle)
		ZwClose(g_EventHandle);

	if(g_pEvent)
		ObDereferenceObject(g_pEvent);
}

NTSTATUS CompleteIrp(PIRP pIrp, NTSTATUS ntStatus, ULONG_PTR info) {
	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = info;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return ntStatus;
}

NTSTATUS SentinelCreateClose(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
	UNREFERENCED_PARAMETER(pDeviceObject);
	return CompleteIrp(pIrp, STATUS_SUCCESS, 0l);
}

NTSTATUS SentinelDeviceControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
	UNREFERENCED_PARAMETER(pDeviceObject);
	ULONG_PTR pLength = 0;
	NTSTATUS ntStatus = STATUS_INVALID_DEVICE_REQUEST;

	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(pIrp);

	switch (pStack->Parameters.DeviceIoControl.IoControlCode) {
		case IOTCTL_SENTINEL_GET_ID:
			if (pStack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(ProcessInfo)) {
				ntStatus = STATUS_BUFFER_TOO_SMALL;
				break;
			}

			ProcessInfo* pProcessInfo = (ProcessInfo*) pIrp->AssociatedIrp.SystemBuffer;
			pProcessInfo->ProcessId = sProcessInfo.ProcessId;
			pProcessInfo->ThreadId = sProcessInfo.ThreadId;
			pLength = sizeof(ProcessInfo);
			ntStatus = STATUS_SUCCESS;
		break;
	}


	sProcessInfo.ProcessId = 0;
	sProcessInfo.ThreadId = 0;
	KeClearEvent(g_pEvent);
	return CompleteIrp(pIrp, ntStatus, pLength);
}

_Use_decl_annotations_
VOID ProcessNotify(_Inout_ PEPROCESS pProcess, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO pCreateInfo) {
	UNREFERENCED_PARAMETER(pProcess);
	
	if (!pCreateInfo)
		return;


	do {
		if (pCreateInfo->ImageFileName && pCreateInfo->ImageFileName->Length > 0) {
			UNICODE_STRING sImageFileName;
			RtlInitUnicodeString(&sImageFileName, pCreateInfo->ImageFileName->Buffer);


			if (wcsstr(sImageFileName.Buffer, L"Sentinel_Threat_Hunter")) {
				KdPrint(("Sentinel Assignature Found in Image File Name. Breaking!\n"));
				break;
			}
		}


		if (pCreateInfo->CommandLine && pCreateInfo->CommandLine->Length > 0) {
			UNICODE_STRING sCommandLine;
			RtlInitUnicodeString(&sCommandLine, pCreateInfo->CommandLine->Buffer);


			if (wcsstr(sCommandLine.Buffer, L"Sentinel_Threat_Hunter")) {
				KdPrint(("Sentinel Assignature Found in Command Line. Breaking!\n"));
				break;
			}
		}

		sProcessInfo.ProcessId = HandleToULong(ProcessId);
		sProcessInfo.ThreadId = HandleToULong(pCreateInfo->CreatingThreadId.UniqueThread);
		KeSetEvent(g_pEvent, 0, FALSE);
		KdPrint(("Sentinel Current IRQL in Process Notify: (0x%02x) With Process Id: %d\n", KeGetCurrentIrql(), sProcessInfo.ProcessId));
	} while (FALSE);
}
