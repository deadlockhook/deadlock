#include "intercept_and_watch.h"
#include "../../../windows/global.h"

_bool_enc watcher::create_hook(_pvoid_enc target_function, _pvoid_enc detour, _pvoid_enc* original) {

    _bool_enc ret = FALSE;

    void* original_out = nullptr;

    if (hooking::minhook::mh_create_hook(target_function.get_decrypted(), detour.get_decrypted(), &original_out) == MH_OK)
    {
        if (original_out && original)
            *original = original_out;

        //   vm_low_start

        PHOOK_ENTRY hook_entry = hooking::minhook::get_hook_entry(target_function.get_decrypted());

        LPBYTE patch_target = (LPBYTE)hook_entry->pTarget;

        SIZE_T patchSize = sizeof(JMP_REL);

        if (hook_entry->patchAbove)
        {
            patch_target -= sizeof(JMP_REL);
            patchSize += sizeof(JMP_REL_SHORT);
        }

        _ulonglong Patch = 0;
        *((char*)&Patch) = 0xE9;
        *((uint32_t*)((uintptr_t)&Patch + 1)) = (uint32_t)((LPBYTE)hook_entry->pDetour - ((LPBYTE)hook_entry->pTarget + sizeof(JMP_REL)));

        if (hook_entry->patchAbove)
        {
            *((char*)((uintptr_t)&Patch + 5)) = 0xEB;
            *((uint8_t*)((uintptr_t)&Patch + 6)) = (uint8_t)(0 - (sizeof(JMP_REL_SHORT) + sizeof(JMP_REL)));
        }

        //  vm_low_end

        watcher::create_hook_watch(watcher::watchdog_patch_walk(FALSE, Patch, patchSize, patch_target, target_function));
        ret = TRUE;
    }

    return ret;
}