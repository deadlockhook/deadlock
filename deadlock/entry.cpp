#define EXE
#include "../windows/global.h"
#include "modules/routines.h"

int _dl_windows_launch() {
    AllocConsole();
    freopen_s(reinterpret_cast<_iobuf**>((__acrt_iob_func)(0)), ("conin$"), ("r"), static_cast<_iobuf*>((__acrt_iob_func)(0)));
    freopen_s(reinterpret_cast<_iobuf**>((__acrt_iob_func)(1)), ("conout$"), ("w"), static_cast<_iobuf*>((__acrt_iob_func)(1)));
    freopen_s(reinterpret_cast<_iobuf**>((__acrt_iob_func)(2)), ("conout$"), ("w"), static_cast<_iobuf*>((__acrt_iob_func)(2)));
    SetConsoleTitleA("deadlock");

    threading::create_thread((threading::fn_thread_callback)watchdog_routines::watchdog, 0);
    return 0;
}

int _dl_windows_shutdown() {

    return 0;
}