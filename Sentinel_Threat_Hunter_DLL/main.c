#include "pch.h"
#include "hooks.h"

#ifdef _M_X64
#pragma comment (lib, "detoursx64.lib")
#endif

#ifdef _M_IX86
#pragma comment (lib, "detoursx86.lib")
#endif


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        printf("\t [ (*) ] Initializing DLL Attach!\n");
        InitializeDetoursHooking();
        break;
    case DLL_PROCESS_DETACH:
        printf("\t [ (*) ] Initializing DLL Detach!\n");
        FreeObjects();
        InitializeDetoursUnhooking();
        break;
    }

    return TRUE;
}