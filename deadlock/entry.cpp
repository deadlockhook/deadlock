#define EXE
#include "../windows/global.h"
#include "modules/routines.h"

int _dl_windows_launch() {
    threading::create_thread((threading::fn_thread_callback)watchdog_routines::watchdog, 0);
    threading::create_thread((threading::fn_thread_callback)watchdog_routines::thread_watch, 0);
    threading::create_thread((threading::fn_thread_callback)watchdog_routines::loaded_dll_watch_routine, 0);
    threading::create_thread((threading::fn_thread_callback)watchdog_routines::handle_watch_routine, 0);
    threading::create_thread((threading::fn_thread_callback)watchdog_routines::external_process_watch_routine, 0);
    execute_call(windows::api::kernel32::SuspendThread, execute_call<HANDLE>(windows::api::kernel32::GetCurrentThread));
    return 0;
}
