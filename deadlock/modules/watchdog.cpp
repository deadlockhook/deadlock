#include "routines.h"
#include "../windows/global.h"
#include "watcher/intercept_and_watch.h"
#include "hooks/hooks.h"

void watchdog_routines::watchdog()
{
    // all hooks must be placed here before watchdog is allowed to watch them
    hooks::initialize();
    watcher::enable_all_hooks();

    threading::create_thread((threading::fn_thread_callback)watchdog_routines::memory_watch, 0);
    threading::create_thread((threading::fn_thread_callback)watchdog_routines::loaded_dll_watch_routine, 0);
    threading::create_thread((threading::fn_thread_callback)watchdog_routines::handle_watch_routine, 0);
    threading::create_thread((threading::fn_thread_callback)watchdog_routines::external_process_watch_routine, 0);
    threading::create_thread((threading::fn_thread_callback)watchdog_routines::patch_walk, 0);
}