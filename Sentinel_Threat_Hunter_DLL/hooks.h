#pragma once

#include "pch.h"
#include "controls.h"

static BOOL(WINAPI* pSetThreadContext) (_In_ HANDLE hThread, _In_ CONST CONTEXT* lpContext) = SetThreadContext;
static LPVOID(WINAPI* pVirtualAllocEx)(_In_ HANDLE hProcess, _In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect) = VirtualAllocEx;
static BOOL(WINAPI* pVirtualProtectEx)(_In_ HANDLE hProcess, _In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect) = VirtualProtectEx;
static LPVOID(WINAPI* pMapViewOfFile)(_In_ HANDLE hFileMappingObject, _In_ DWORD dwDesiredAccess, _In_ DWORD dwFileOffsetHigh, _In_ DWORD dwFileOffsetLow, _In_ SIZE_T dwNumberOfBytesToMap) = MapViewOfFile;
static BOOL(WINAPI* pWriteFile)(_In_ HANDLE hFile, _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer, _In_ DWORD nNumberOfBytesToWrite, _Out_opt_ LPDWORD lpNumberOfBytesWritten, _Inout_opt_ LPOVERLAPPED lpOverlapped) = WriteFile;
static HANDLE(WINAPI* pCreateFileMappingA)(_In_ HANDLE hFile, _In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes, _In_ DWORD flProtect, _In_ DWORD dwMaximumSizeHigh, _In_ DWORD dwMaximumSizeLow, _In_opt_ LPCSTR lpName) = CreateFileMappingA;
static HANDLE(WINAPI* pCreateFileA)(_In_ LPCSTR lpFileName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwShareMode, _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes, _In_ DWORD dwCreationDisposition, _In_ DWORD dwFlagsAndAttributes, _In_opt_ HANDLE hTemplateFile) = CreateFileA;
static HANDLE(WINAPI* pCreateRemoteThread)(_In_ HANDLE hProcess, _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes, _In_ SIZE_T dwStackSize, _In_ LPTHREAD_START_ROUTINE lpStartAddress, _In_opt_ LPVOID lpParameter, _In_ DWORD dwCreationFlags, _Out_opt_ LPDWORD lpThreadId) = CreateRemoteThread;

BOOL InitializeDetoursHooking();
BOOL InitializeDetoursUnhooking();

static BOOL HookedSetThreadContext(_In_ HANDLE hThread, _In_ CONST CONTEXT* lpContext);
static BOOL HookedVirtualProtectEx(_In_ HANDLE hProcess, _In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);
static LPVOID HookedVirtualAllocEx(_In_ HANDLE hProcess, _In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect);
static LPVOID HookedMapViewOfFile(_In_ HANDLE hFileMappingObject, _In_ DWORD dwDesiredAccess, _In_ DWORD dwFileOffsetHigh, _In_ DWORD dwFileOffsetLow, _In_ SIZE_T dwNumberOfBytesToMap);
static HANDLE HookedCreateFileMappingA(_In_ HANDLE hFile, _In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes, _In_ DWORD flProtect, _In_ DWORD dwMaximumSizeHigh, _In_ DWORD dwMaximumSizeLow, _In_opt_ LPCSTR lpName);
static BOOL HookedWriteFile(_In_ HANDLE hFile, _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer, _In_ DWORD nNumberOfBytesToWrite, _Out_opt_ LPDWORD lpNumberOfBytesWritten, _Inout_opt_ LPOVERLAPPED lpOverlapped);
static HANDLE HookedCreateFileA(_In_ LPCSTR lpFileName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwShareMode, _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes, _In_ DWORD dwCreationDisposition, _In_ DWORD dwFlagsAndAttributes, _In_opt_ HANDLE hTemplateFile);
static HANDLE HookeCreateRemoteThread(_In_ HANDLE hProcess, _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes, _In_ SIZE_T dwStackSize, _In_ LPTHREAD_START_ROUTINE lpStartAddress, _In_opt_ LPVOID lpParameter, _In_ DWORD dwCreationFlags, _Out_opt_ LPDWORD lpThreadId);