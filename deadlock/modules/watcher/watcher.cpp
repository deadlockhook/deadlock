#include "intercept_and_watch.h"
#include "../../../windows/global.h"

 _bool_enc watcher::patch_watch_already_exist(_pvoid_enc target_function) {

    _bool_enc ret = FALSE;
    hook_watch_lock.lock();
    for (auto& current : vec_patch_walk)
    {
        if (current.target_function.get_decrypted() == target_function.get_decrypted()) {
            ret = TRUE;
            break;
        }
    }
    hook_watch_lock.release();

    return ret;
}

 void watcher::remove_patch_walk(_pvoid_enc target_function) {
    hook_watch_lock.lock();

    for (auto it = watcher::vec_patch_walk.begin(); it != watcher::vec_patch_walk.end(); )
    {
        auto current = &*it;

        if (current->target_function.get_decrypted() == target_function.get_decrypted())
            it = watcher::vec_patch_walk.erase(it);
        else
            it = next(it);
    }

    hook_watch_lock.release();
}

 void watcher::create_patch_watch(_pvoid_enc target_function, _lpcstr_enc function_name_ptr, _lpcwstr_enc module_name_ptr) {

    _bool_enc patch_walk_exist = watcher::patch_watch_already_exist(target_function);

    hook_watch_lock.lock();

    if (!patch_walk_exist.get_decrypted())
    {
        vec_patch_walk.emplace_back(watchdog_patch_walk(TRUE, *((unsigned long long*)target_function.get_decrypted()), sizeof(unsigned long long),
            target_function, target_function, function_name_ptr, module_name_ptr));

    }
    hook_watch_lock.release();
}

 void watcher::create_hook_watch(watchdog_patch_walk hook) {

    auto _hook = hook;

    hook_watch_lock.lock();

    for (auto it = watcher::vec_patch_walk.begin(); it != watcher::vec_patch_walk.end(); )
    {
        auto current = &*it;

        auto _current = *current;

        if (_current.target_function.get_decrypted() == _hook.target_function.get_decrypted()) {
            it = watcher::vec_patch_walk.erase(it);
            _hook.function_name_ptr = _current.function_name_ptr;
            _hook.module_name_ptr = _current.module_name_ptr;
        }
        else
            it = next(it);
    }

    vec_patch_walk.emplace_back(hook);
    hook_watch_lock.release();
}

 _bool_enc watcher::remove_hook(_pvoid_enc target_function) {
    _bool_enc ret = FALSE;

    watcher::hook_watch_lock.lock();

    for (auto it = watcher::vec_patch_walk.begin(); it != watcher::vec_patch_walk.end(); it++)
    {
        auto hook = &*it;

        if (hook->target_function.get_decrypted() == target_function.get_decrypted())
        {
            hooking::minhook::mh_remove_hook(target_function.get_decrypted());

            watcher::vec_patch_walk.erase(it);
            ret = TRUE;
            break;
        }
    }


    watcher::hook_watch_lock.release();

    return ret;
}

 _bool_enc watcher::enable_hook(_pvoid_enc target_function) {

   // vm_low_start

        _bool_enc ret = FALSE;

    watcher::hook_watch_lock.lock();

    for (auto it = watcher::vec_patch_walk.begin(); it != watcher::vec_patch_walk.end(); it++)
    {
        auto hook = &*it;

        if (hook->target_function.get_decrypted() == target_function.get_decrypted())
        {
            auto hook_dcr = *hook;

            hooking::minhook::mh_enable_hook(target_function.get_decrypted());

            hook_dcr.enabled = TRUE;

            *hook = hook_dcr;
            ret = TRUE;
            break;
        }
    }

    watcher::hook_watch_lock.release();

   // vm_low_end

        return ret;
}

_bool_enc watcher::enable_all_hooks() {
    _bool_enc ret = FALSE;

    watcher::hook_watch_lock.lock();

    if (watcher::vec_patch_walk.size()) {

        ret = TRUE;

        for (auto it = watcher::vec_patch_walk.begin(); it != watcher::vec_patch_walk.end(); it++)
        {
            auto hook = &*it;

            auto hook_dcr = *hook;

            if (!hook_dcr.enabled.get_decrypted()) {
                hook_dcr.enabled = hooking::minhook::mh_enable_hook(hook_dcr.target_function.get_decrypted()) == MH_OK;
                if (!hook_dcr.enabled.get_decrypted())
                {
                    ret = FALSE;
                    break;
                }
            }

            *hook = hook_dcr;
        }

    }
    else
        ret = TRUE;

    watcher::hook_watch_lock.release();
    return ret;
}

