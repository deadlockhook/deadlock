#include "minhook.h"
#include "../../winapi/wrapper.h"
#include "../../memory/memory.h"

#ifndef ARRAYSIZE
#define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif

#define INITIAL_HOOK_CAPACITY   32

#define INITIAL_THREAD_CAPACITY 128

#define INVALID_HOOK_POS UINT_MAX
#define ALL_HOOKS_POS    UINT_MAX

#define ACTION_DISABLE      0
#define ACTION_ENABLE       1
#define ACTION_APPLY_QUEUED 2

#define THREAD_ACCESS \
    (THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT)

typedef struct _FROZEN_THREADS
{
    LPDWORD pItems;
    UINT    capacity;
    UINT    size;
} FROZEN_THREADS, * PFROZEN_THREADS;

volatile LONG g_isLocked = FALSE;

struct
{
    PHOOK_ENTRY pItems;
    UINT        capacity;
    UINT        size;
} g_hooks;

static __declspec(noinline) UINT FindHookEntry(LPVOID pTarget)
{
    UINT i;
    for (i = 0; i < g_hooks.size; ++i)
    {
        if ((ULONG_PTR)pTarget == (ULONG_PTR)g_hooks.pItems[i].pTarget)
            return i;
    }

    return INVALID_HOOK_POS;
}

static __declspec(noinline) PHOOK_ENTRY AddHookEntry()
{

    if (g_hooks.pItems == NULL)
    {
        g_hooks.capacity = INITIAL_HOOK_CAPACITY;
        g_hooks.pItems = (PHOOK_ENTRY)memory::_malloc(g_hooks.capacity * sizeof(HOOK_ENTRY)).get_decrypted();

        if (g_hooks.pItems == NULL)
            return NULL;
    }
    else if (g_hooks.size >= g_hooks.capacity)
    {
        PHOOK_ENTRY p = (PHOOK_ENTRY)memory::_realloc(g_hooks.pItems, (g_hooks.capacity * 2) * sizeof(HOOK_ENTRY)).get_decrypted();

        if (p == NULL)
            return NULL;

        g_hooks.capacity *= 2;
        g_hooks.pItems = p;
    }

    return &g_hooks.pItems[g_hooks.size++];
}

static __declspec(noinline) VOID DeleteHookEntry(UINT pos)
{
    if (pos < g_hooks.size - 1)
        g_hooks.pItems[pos] = g_hooks.pItems[g_hooks.size - 1];

    g_hooks.size--;

    if (g_hooks.capacity / 2 >= INITIAL_HOOK_CAPACITY && g_hooks.capacity / 2 >= g_hooks.size)
    {
        PHOOK_ENTRY p = (PHOOK_ENTRY)memory::_realloc(g_hooks.pItems, (g_hooks.capacity / 2) * sizeof(HOOK_ENTRY)).get_decrypted();

        if (p == NULL)
            return;

        g_hooks.capacity /= 2;
        g_hooks.pItems = p;
    }
}

static __declspec(noinline) DWORD_PTR FindOldIP(PHOOK_ENTRY pHook, DWORD_PTR ip)
{
    UINT i;

    if (pHook->patchAbove && ip == ((DWORD_PTR)pHook->pTarget - sizeof(JMP_REL)))
        return (DWORD_PTR)pHook->pTarget;

    for (i = 0; i < pHook->nIP; ++i)
    {
        if (ip == ((DWORD_PTR)pHook->pTrampoline + pHook->newIPs[i]))
            return (DWORD_PTR)pHook->pTarget + pHook->oldIPs[i];
    }

    if (ip == (DWORD_PTR)pHook->pDetour)
        return (DWORD_PTR)pHook->pTarget;

    return 0;
}

static __declspec(noinline) DWORD_PTR FindNewIP(PHOOK_ENTRY pHook, DWORD_PTR ip)
{
    UINT i;
    for (i = 0; i < pHook->nIP; ++i)
    {
        if (ip == ((DWORD_PTR)pHook->pTarget + pHook->oldIPs[i]))
            return (DWORD_PTR)pHook->pTrampoline + pHook->newIPs[i];
    }

    return 0;
}

static __declspec(noinline) VOID ProcessThreadIPs(HANDLE hThread, UINT pos, UINT action)
{

    CONTEXT c;
    DWORD64* pIP = &c.Rip;
    UINT count;

    c.ContextFlags = CONTEXT_CONTROL;

    if (!execute_call<BOOL>(windows::api::kernel32::GetThreadContext, hThread, &c))
        return;

    if (pos == ALL_HOOKS_POS)
    {
        pos = 0;
        count = g_hooks.size;
    }
    else
    {
        count = pos + 1;
    }

    for (; pos < count; ++pos)
    {
        PHOOK_ENTRY pHook = &g_hooks.pItems[pos];
        BOOL        enable;
        DWORD_PTR   ip;

        switch (action)
        {
        case ACTION_DISABLE:
            enable = FALSE;
            break;

        case ACTION_ENABLE:
            enable = TRUE;
            break;

        default:
            break;
        }
        if (pHook->isEnabled == enable)
            continue;

        if (enable)
            ip = FindNewIP(pHook, *pIP);
        else
            ip = FindOldIP(pHook, *pIP);

        if (ip != 0)
        {
            *pIP = ip;
            execute_call<BOOL>(windows::api::kernel32::SetThreadContext, hThread, &c);
        }
    }

}

static __declspec(noinline) BOOL EnumerateThreads(PFROZEN_THREADS pThreads)
{

    BOOL succeeded = FALSE;

    HANDLE hSnapshot = execute_call<HANDLE>(windows::api::kernel32::CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, 0);

    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        if (execute_call<BOOL>(windows::api::kernel32::Thread32First, hSnapshot, &te))
        {
            succeeded = TRUE;
            do
            {
                if (te.dwSize >= (FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(DWORD))
                    && te.th32OwnerProcessID == windows::local_app_data::process_id.get_decrypted()
                    && te.th32ThreadID != execute_call<DWORD>(windows::api::kernel32::GetCurrentThreadId))
                {
                    if (pThreads->pItems == NULL)
                    {
                        pThreads->capacity = INITIAL_THREAD_CAPACITY;

                        pThreads->pItems = (LPDWORD)memory::_malloc(pThreads->capacity * sizeof(DWORD)).get_decrypted();

                        if (pThreads->pItems == NULL)
                        {
                            succeeded = FALSE;
                            break;
                        }
                    }
                    else if (pThreads->size >= pThreads->capacity)
                    {
                        pThreads->capacity *= 2;
                        LPDWORD p = (LPDWORD)memory::_realloc(pThreads->pItems, pThreads->capacity * sizeof(DWORD)).get_decrypted();

                        if (p == NULL)
                        {
                            succeeded = FALSE;
                            break;
                        }

                        pThreads->pItems = p;
                    }
                    pThreads->pItems[pThreads->size++] = te.th32ThreadID;
                }

                te.dwSize = sizeof(THREADENTRY32);
            } while (execute_call<BOOL>(windows::api::kernel32::Thread32Next, hSnapshot, &te));

            if (succeeded && execute_call<DWORD>(windows::api::kernel32::GetLastError) != ERROR_NO_MORE_FILES)
                succeeded = FALSE;

            if (!succeeded && pThreads->pItems != NULL)
            {
                memory::_free(pThreads->pItems);
                pThreads->pItems = NULL;
            }
        }

        execute_call<BOOL>(windows::api::kernel32::CloseHandle, hSnapshot);
    }

    return succeeded;
}

static __declspec(noinline) MH_STATUS Freeze(PFROZEN_THREADS pThreads, UINT pos, UINT action)
{

    MH_STATUS status = MH_OK;

    pThreads->pItems = NULL;
    pThreads->capacity = 0;
    pThreads->size = 0;
    if (!EnumerateThreads(pThreads))
    {
        status = MH_ERROR_MEMORY_ALLOC;
    }
    else if (pThreads->pItems != NULL)
    {

        UINT i;
        for (i = 0; i < pThreads->size; ++i)
        {
            HANDLE hThread = execute_call<HANDLE>(windows::api::kernel32::OpenThread, THREAD_ACCESS, FALSE, pThreads->pItems[i]);
            if (hThread != NULL)
            {
                execute_call(windows::api::kernel32::SuspendThread, hThread);
                ProcessThreadIPs(hThread, pos, action);
                execute_call(windows::api::kernel32::CloseHandle, hThread);
            }
        }
    }

    return status;
}

static __declspec(noinline) VOID Unfreeze(PFROZEN_THREADS pThreads)
{
    if (pThreads->pItems != NULL)
    {
        UINT i;
        for (i = 0; i < pThreads->size; ++i)
        {


            HANDLE hThread = execute_call<HANDLE>(windows::api::kernel32::OpenThread, THREAD_ACCESS, FALSE, pThreads->pItems[i]);
            if (hThread != NULL)
            {
                execute_call(windows::api::kernel32::ResumeThread, hThread);
                execute_call(windows::api::kernel32::CloseHandle, hThread);
            }
        }

        memory::_free(pThreads->pItems);
    }
}

static __declspec(noinline) MH_STATUS EnableHookLL(UINT pos, BOOL enable)
{

    PHOOK_ENTRY pHook = &g_hooks.pItems[pos];
    DWORD  oldProtect;
    SIZE_T patchSize = sizeof(JMP_REL);
    LPBYTE pPatchTarget = (LPBYTE)pHook->pTarget;

    if (pHook->patchAbove)
    {
        pPatchTarget -= sizeof(JMP_REL);
        patchSize += sizeof(JMP_REL_SHORT);
    }

    if (!execute_call<BOOL>(windows::api::kernel32::VirtualProtect, pPatchTarget, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        return MH_ERROR_MEMORY_PROTECT;

    if (enable)
    {
        PJMP_REL pJmp = (PJMP_REL)pPatchTarget;
        pJmp->opcode = 0xE9;
        pJmp->operand = (uint32_t)((LPBYTE)pHook->pDetour - (pPatchTarget + sizeof(JMP_REL)));

        if (pHook->patchAbove)
        {
            PJMP_REL_SHORT pShortJmp = (PJMP_REL_SHORT)pHook->pTarget;
            pShortJmp->opcode = 0xEB;
            pShortJmp->operand = (uint8_t)(0 - (sizeof(JMP_REL_SHORT) + sizeof(JMP_REL)));
        }
    }
    else
    {
        if (pHook->patchAbove)
            _memcpy(pPatchTarget, pHook->backup, sizeof(JMP_REL) + sizeof(JMP_REL_SHORT));
        else
            _memcpy(pPatchTarget, pHook->backup, sizeof(JMP_REL));
    }


    execute_call(windows::api::kernel32::VirtualProtect, pPatchTarget, patchSize, oldProtect, &oldProtect);
    execute_call(windows::api::kernel32::FlushInstructionCache, windows::local_app_data::process_handle.get_decrypted(), pPatchTarget, patchSize);

    pHook->isEnabled = enable;

    return MH_OK;
}

static __declspec(noinline) MH_STATUS EnableAllHooksLL(BOOL enable)
{
    //m_start

    MH_STATUS status = MH_OK;
    UINT i, first = INVALID_HOOK_POS;

    for (i = 0; i < g_hooks.size; ++i)
    {
        if (g_hooks.pItems[i].isEnabled != enable)
        {
            first = i;
            break;
        }
    }

    if (first != INVALID_HOOK_POS)
    {
        FROZEN_THREADS threads;
        status = Freeze(&threads, ALL_HOOKS_POS, enable ? ACTION_ENABLE : ACTION_DISABLE);
        if (status == MH_OK)
        {
            for (i = first; i < g_hooks.size; ++i)
            {
                if (g_hooks.pItems[i].isEnabled != enable)
                {
                    status = EnableHookLL(i, enable);
                    if (status != MH_OK)
                        break;
                }
            }

            Unfreeze(&threads);
        }
    }

    //m_end

    return status;
}

static __declspec(noinline) VOID EnterSpinLock(VOID)
{

    SIZE_T spinCount = 0;

    while (InterlockedCompareExchange(&g_isLocked, TRUE, FALSE) != FALSE)
    {
        if (spinCount < 32)
            execute_call(windows::api::kernel32::Sleep, 0);
        else
            execute_call(windows::api::kernel32::Sleep, 1);

        spinCount++;
    }
}

static __declspec(noinline) VOID LeaveSpinLock(VOID)
{
    InterlockedExchange(&g_isLocked, FALSE);
}

__declspec(noinline) MH_STATUS hooking::minhook::mh_destroy(VOID)
{
    MH_STATUS status = MH_OK;

    EnterSpinLock();

    status = EnableAllHooksLL(FALSE);
    if (status == MH_OK)
    {
        mh_buffer_destroy();
        memory::_free(g_hooks.pItems);
        g_hooks.pItems = NULL;
        g_hooks.capacity = 0;
        g_hooks.size = 0;
    }

    LeaveSpinLock();

    return status;
}

__declspec(noinline) MH_STATUS hooking::minhook::mh_create_hook(LPVOID pTarget, LPVOID pDetour, LPVOID* ppOriginal)
{
   // vm_low_start

        MH_STATUS status = MH_OK;

    EnterSpinLock();


    if (mh_buffer_is_executable_address(pTarget) && mh_buffer_is_executable_address(pDetour))
    {
        UINT pos = FindHookEntry(pTarget);
        if (pos == INVALID_HOOK_POS)
        {
            LPVOID pBuffer = mh_buffer_allocate(pTarget);
            if (pBuffer != NULL)
            {
                TRAMPOLINE ct;

                ct.pTarget = pTarget;
                ct.pDetour = pDetour;
                ct.pTrampoline = pBuffer;
                if (create_trampoline_function(&ct))
                {

                    PHOOK_ENTRY pHook = AddHookEntry();
                    if (pHook != NULL)
                    {

                        pHook->pTarget = ct.pTarget;
                        pHook->pDetour = ct.pRelay;
                        pHook->pTrampoline = ct.pTrampoline;
                        pHook->patchAbove = ct.patchAbove;
                        pHook->isEnabled = FALSE;
                        pHook->nIP = ct.nIP;
                        _memcpy(pHook->oldIPs, ct.oldIPs, ARRAYSIZE(ct.oldIPs));
                        _memcpy(pHook->newIPs, ct.newIPs, ARRAYSIZE(ct.newIPs));

                        if (ct.patchAbove)
                        {
                            _memcpy(
                                pHook->backup,
                                (LPBYTE)pTarget - sizeof(JMP_REL),
                                sizeof(JMP_REL) + sizeof(JMP_REL_SHORT));
                        }
                        else
                        {
                            _memcpy(pHook->backup, pTarget, sizeof(JMP_REL));
                        }

                        if (ppOriginal != NULL)
                            *ppOriginal = pHook->pTrampoline;
                    }
                    else
                    {
                        status = MH_ERROR_MEMORY_ALLOC;
                    }
                }
                else
                {
                    status = MH_ERROR_UNSUPPORTED_FUNCTION;
                }

                if (status != MH_OK)
                {
                    mh_buffer_free(pBuffer);
                }
            }
            else
            {
                status = MH_ERROR_MEMORY_ALLOC;
            }
        }
        else
        {
            status = MH_ERROR_ALREADY_CREATED;
        }
    }
    else
    {
        status = MH_ERROR_NOT_EXECUTABLE;
    }

    LeaveSpinLock();

  //  vm_low_end

        return status;
}

__declspec(noinline) MH_STATUS hooking::minhook::mh_remove_hook(LPVOID pTarget)
{
    MH_STATUS status = MH_OK;

  //  vm_low_start

        EnterSpinLock();


    UINT pos = FindHookEntry(pTarget);
    if (pos != INVALID_HOOK_POS)
    {
        if (g_hooks.pItems[pos].isEnabled)
        {
            FROZEN_THREADS threads;
            status = Freeze(&threads, pos, ACTION_DISABLE);
            if (status == MH_OK)
            {
                status = EnableHookLL(pos, FALSE);

                Unfreeze(&threads);
            }
        }

        if (status == MH_OK)
        {
            mh_buffer_free(g_hooks.pItems[pos].pTrampoline);
            DeleteHookEntry(pos);
        }
    }
    else
    {
        status = MH_ERROR_NOT_CREATED;
    }

    LeaveSpinLock();

  //  vm_low_end

        return status;
}

__declspec(noinline) MH_STATUS  hooking::minhook::enable_hook_ex(LPVOID pTarget, BOOL enable)
{
  //  vm_low_start

        MH_STATUS status = MH_OK;

    EnterSpinLock();


    if (pTarget == MH_ALL_HOOKS)
    {
        status = EnableAllHooksLL(enable);
    }
    else
    {
        UINT pos = FindHookEntry(pTarget);
        if (pos != INVALID_HOOK_POS)
        {
            if (g_hooks.pItems[pos].isEnabled != enable)
            {
                FROZEN_THREADS threads;
                status = MH_OK;
                status = Freeze(&threads, pos, ACTION_ENABLE);
                if (status == MH_OK)
                {
                    status = EnableHookLL(pos, enable);

                    Unfreeze(&threads);
                }
            }
            else
            {
                status = enable ? MH_ERROR_ENABLED : MH_ERROR_DISABLED;
            }
        }
        else
        {
            status = MH_ERROR_NOT_CREATED;
        }
    }

    LeaveSpinLock();

  //  vm_low_end

        return status;
}


__declspec(noinline) PHOOK_ENTRY hooking::minhook::get_hook_entry(LPVOID pTarget)
{
    UINT pos = FindHookEntry(pTarget);

    if (pos != INVALID_HOOK_POS)
    {
        return &g_hooks.pItems[pos];
    }

    return nullptr;
}
