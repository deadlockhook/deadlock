#pragma once
#include "../windows/global.h"

namespace watcher {
    struct watchdog_pointer_watch
    {
        _ulonglong_enc target_pointer_location;
        _ulonglong_enc target_destination;
        _ulonglong_enc module_start;
        _ulonglong_enc module_end;
    };

    struct watchdog_patch_walk
    {
        _bool_enc enabled = FALSE;
        _ulonglong_enc patch;
        _ulonglong_enc patch_size = 0;
        _pvoid_enc patch_target = 0;
        _pvoid_enc target_function = 0;
        _lpcstr_enc function_name_ptr;
        _lpcwstr_enc module_name_ptr;
    };

    inline atomic::critical_section hook_watch_lock;
    inline secure_vector<watchdog_patch_walk> vec_patch_walk;

    _bool_enc patch_watch_already_exist(_pvoid_enc target_function);
    void remove_patch_walk(_pvoid_enc target_function);
    void create_patch_watch(_pvoid_enc target_function, _lpcstr_enc function_name_ptr, _lpcwstr_enc module_name_ptr);
    void create_hook_watch(watchdog_patch_walk hook);

    _bool_enc remove_hook(_pvoid_enc target_function);
    _bool_enc enable_hook(_pvoid_enc target_function);
    _bool_enc enable_all_hooks();
    _bool_enc create_hook(_pvoid_enc target_function, _pvoid_enc detour, _pvoid_enc* original);
}




