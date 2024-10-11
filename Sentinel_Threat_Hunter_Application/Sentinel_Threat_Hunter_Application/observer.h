#pragma once

#include "pch.h"

_Use_decl_anno_impl_ VOID DirectoryChangesAnalyzer(POBSERVERARGUMENTS* pThreadArguments);

_Use_decl_anno_impl_ VOID DirectoryChangesObserver(POBSERVERARGUMENTS* pThreadArguments);

BOOL GetUserDirectory(WCHAR sUserDirectoryPath[]);

static BOOL RealizeStaticAnalysis(WCHAR sYaraPath[], WCHAR sYaraRulePath[], WCHAR sUserDirectoryPath[], WCHAR sFileName[]);