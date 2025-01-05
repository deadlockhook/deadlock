#include "global.h"

/*
extern "C" void mainCRTStartup();

int main()
{
    return _dl_windows_launch();
}

void _start() {
	encryption::initialize();
    windows::initialize();
    memory::initialize();
    mainCRTStartup();
}
*/

extern "C" BOOL WINAPI _DllMainCRTStartup(HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpReserved);

BOOL WINAPI _start(HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpReserved) {

    if (fdwReason == DLL_PROCESS_ATTACH) {
        encryption::initialize();
        windows::initialize();
        memory::initialize();
    }

    if (!_DllMainCRTStartup(hinstDLL,
        fdwReason,
        lpReserved))
        return FALSE;

    if (fdwReason == DLL_PROCESS_ATTACH) 
        _dl_windows_launch();

    if (fdwReason == DLL_PROCESS_DETACH) 
        _dl_windows_shutdown();
    

    return TRUE;
}


