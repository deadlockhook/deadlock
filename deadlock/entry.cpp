#define EXE
#include "../windows/global.h"
#include "modules/watchdog.h"


int _dl_windows_launch() {
    threading::create_thread((threading::fn_thread_callback)modules::userapc_routine, 0);
    threading::create_thread((threading::fn_thread_callback)modules::loaded_dll_watch_routine, 0);
    threading::create_thread((threading::fn_thread_callback)modules::handle_watch_routine, 0);
    threading::create_thread((threading::fn_thread_callback)modules::external_process_watch_routine, 0);
    execute_call(windows::api::kernel32::SuspendThread, execute_call<HANDLE>(windows::api::kernel32::GetCurrentThread));
    return 0;
}
