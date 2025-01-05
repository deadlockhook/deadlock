#include "routines.h"
#include "../windows/global.h"

void watchdog_routines::watchdog()
{
    threading::create_thread((threading::fn_thread_callback)watchdog_routines::memory_watch, 0);
    threading::create_thread((threading::fn_thread_callback)watchdog_routines::loaded_dll_watch_routine, 0);
    threading::create_thread((threading::fn_thread_callback)watchdog_routines::handle_watch_routine, 0);
    threading::create_thread((threading::fn_thread_callback)watchdog_routines::external_process_watch_routine, 0);
}