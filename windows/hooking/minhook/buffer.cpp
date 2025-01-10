#include "minhook.h"
#include "../../winapi/wrapper.h"
#include "../../memory/memory.h"

using namespace windows;

#define MEMORY_BLOCK_SIZE 0x1000
#define MAX_MEMORY_RANGE 0x40000000

#define PAGE_EXECUTE_FLAGS \
    (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

typedef struct _MEMORY_SLOT
{
    union
    {
        struct _MEMORY_SLOT *pNext;
        uint8_t buffer[MEMORY_SLOT_SIZE];
    };
} MEMORY_SLOT, *PMEMORY_SLOT;

typedef struct _MEMORY_BLOCK
{
    struct _MEMORY_BLOCK *pNext;
    PMEMORY_SLOT pFree;         
    UINT usedCount;
} MEMORY_BLOCK, *PMEMORY_BLOCK;

PMEMORY_BLOCK g_pMemoryBlocks;

 VOID hooking::minhook::mh_buffer_destroy(VOID)
{
    PMEMORY_BLOCK pBlock = g_pMemoryBlocks;
    g_pMemoryBlocks = NULL;

    while (pBlock)
    {
        PMEMORY_BLOCK pNext = pBlock->pNext;
        execute_call<LPVOID>(windows::api::kernel32::VirtualFree, pBlock, (SIZE_T)0, MEM_RELEASE);
        pBlock = pNext;
    }
}
 LPVOID FindPrevFreeRegion(LPVOID pAddress, LPVOID pMinAddr, DWORD dwAllocationGranularity)
{
    // vm_low_start

    ULONG_PTR tryAddr = (ULONG_PTR)pAddress;

    tryAddr -= tryAddr % dwAllocationGranularity;

    tryAddr -= dwAllocationGranularity;

    while (tryAddr >= (ULONG_PTR)pMinAddr)
    {
        encryption::encrypted_block<MEMORY_BASIC_INFORMATION> _mbi;

        if (!memory::query_virtual_memory((void*)tryAddr, _mbi).get_decrypted())
            break;

        auto mbi = _mbi.get_decrypted();

        if (mbi.State == MEM_FREE)
            return (LPVOID)tryAddr;

        if ((ULONG_PTR)mbi.AllocationBase < dwAllocationGranularity)
            break;

        tryAddr = (ULONG_PTR)mbi.AllocationBase - dwAllocationGranularity;
    }

   // vm_low_end

    return NULL;
}

LPVOID FindNextFreeRegion(LPVOID pAddress, LPVOID pMaxAddr, DWORD dwAllocationGranularity)
{
  //  vm_low_start

    ULONG_PTR tryAddr = (ULONG_PTR)pAddress;

    tryAddr -= tryAddr % dwAllocationGranularity;
    tryAddr += dwAllocationGranularity;

    while (tryAddr <= (ULONG_PTR)pMaxAddr)
    {
        encryption::encrypted_block<MEMORY_BASIC_INFORMATION> _mbi;

        if (!memory::query_virtual_memory((void*)tryAddr, _mbi).get_decrypted())
            break;

        auto mbi = _mbi.get_decrypted();

        if (mbi.State == MEM_FREE)
            return (LPVOID)tryAddr;

        tryAddr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;

        tryAddr += dwAllocationGranularity - 1;
        tryAddr -= tryAddr % dwAllocationGranularity;
    }
   // vm_low_end

    return NULL;
}

PMEMORY_BLOCK GetMemoryBlock(LPVOID pOrigin)
{
  //  vm_low_start

    PMEMORY_BLOCK pBlock;
    ULONG_PTR minAddr;
    ULONG_PTR maxAddr;

    SYSTEM_INFO si;
    execute_call(windows::api::kernel32::GetSystemInfo,&si);
    minAddr = (ULONG_PTR)si.lpMinimumApplicationAddress;
    maxAddr = (ULONG_PTR)si.lpMaximumApplicationAddress;

    if ((ULONG_PTR)pOrigin > MAX_MEMORY_RANGE && minAddr < (ULONG_PTR)pOrigin - MAX_MEMORY_RANGE)
        minAddr = (ULONG_PTR)pOrigin - MAX_MEMORY_RANGE;

    if (maxAddr > (ULONG_PTR)pOrigin + MAX_MEMORY_RANGE)
        maxAddr = (ULONG_PTR)pOrigin + MAX_MEMORY_RANGE;

    maxAddr -= MEMORY_BLOCK_SIZE - 1;

    for (pBlock = g_pMemoryBlocks; pBlock != NULL; pBlock = pBlock->pNext)
    {

        if ((ULONG_PTR)pBlock < minAddr || (ULONG_PTR)pBlock >= maxAddr)
            continue;

        if (pBlock->pFree != NULL)
            return pBlock;
    }

    {
        LPVOID pAlloc = pOrigin;
        while ((ULONG_PTR)pAlloc >= minAddr)
        {
            pAlloc = FindPrevFreeRegion(pAlloc, (LPVOID)minAddr, si.dwAllocationGranularity);
            if (pAlloc == NULL)
                break;
          
            pBlock = (PMEMORY_BLOCK)execute_call<LPVOID>(windows::api::kernel32::VirtualAlloc,
             pAlloc, (SIZE_T)MEMORY_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
           
            if (pBlock != NULL)
                break;
        }
    }

    if (pBlock == NULL)
    {
        LPVOID pAlloc = pOrigin;
        while ((ULONG_PTR)pAlloc <= maxAddr)
        {
            pAlloc = FindNextFreeRegion(pAlloc, (LPVOID)maxAddr, si.dwAllocationGranularity);
            if (pAlloc == NULL)
                break;

            pBlock = (PMEMORY_BLOCK)execute_call<LPVOID>(windows::api::kernel32::VirtualAlloc,
                pAlloc, (SIZE_T)MEMORY_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (pBlock != NULL)
                break;
        }
    }

    if (pBlock != NULL)
    {
        PMEMORY_SLOT pSlot = (PMEMORY_SLOT)pBlock + 1;
        pBlock->pFree = NULL;
        pBlock->usedCount = 0;
        do
        {
            pSlot->pNext = pBlock->pFree;
            pBlock->pFree = pSlot;
            pSlot++;
        } while ((ULONG_PTR)pSlot - (ULONG_PTR)pBlock <= MEMORY_BLOCK_SIZE - MEMORY_SLOT_SIZE);

        pBlock->pNext = g_pMemoryBlocks;
        g_pMemoryBlocks = pBlock;
    }
    //vm_low_end

    return pBlock;
}

 LPVOID hooking::minhook::mh_buffer_allocate(LPVOID pOrigin)
{
    PMEMORY_SLOT  pSlot;
    PMEMORY_BLOCK pBlock = GetMemoryBlock(pOrigin);
    if (pBlock == NULL)
        return NULL;

    pSlot = pBlock->pFree;
    pBlock->pFree = pSlot->pNext;
    pBlock->usedCount++;

    return pSlot;
}

__declspec(noinline) VOID hooking::minhook::mh_buffer_free(LPVOID pBuffer)
{
  //  vm_low_start

    PMEMORY_BLOCK pBlock = g_pMemoryBlocks;
    PMEMORY_BLOCK pPrev = NULL;
    ULONG_PTR pTargetBlock = ((ULONG_PTR)pBuffer / MEMORY_BLOCK_SIZE) * MEMORY_BLOCK_SIZE;

    while (pBlock != NULL)
    {
        if ((ULONG_PTR)pBlock == pTargetBlock)
        {
            PMEMORY_SLOT pSlot = (PMEMORY_SLOT)pBuffer;

            pSlot->pNext = pBlock->pFree;
            pBlock->pFree = pSlot;
            pBlock->usedCount--;

            if (pBlock->usedCount == 0)
            {
                if (pPrev)
                    pPrev->pNext = pBlock->pNext;
                else
                    g_pMemoryBlocks = pBlock->pNext;

                execute_call<BOOL>(windows::api::kernel32::VirtualFree,pBlock, (SIZE_T)0, MEM_RELEASE);
            }

            break;
        }

        pPrev = pBlock;
        pBlock = pBlock->pNext;
    }

   // vm_low_end
}

__declspec(noinline) BOOL hooking::minhook::mh_buffer_is_executable_address(LPVOID pAddress)
{
    encryption::encrypted_block<MEMORY_BASIC_INFORMATION> _mbi;

    if (!memory::query_virtual_memory(pAddress, _mbi).get_decrypted())
        FALSE;

    MEMORY_BASIC_INFORMATION mi = _mbi.get_decrypted();
    return (mi.State == MEM_COMMIT && (mi.Protect & PAGE_EXECUTE_FLAGS));
}
