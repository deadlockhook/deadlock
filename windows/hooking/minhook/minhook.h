#pragma once

#include "../../common.h"

//credits https://github.com/TsudaKageyu/minhook

#define MH_ALL_HOOKS NULL

typedef enum MH_STATUS
{
    MH_UNKNOWN = -1,
    MH_OK = 0,
    MH_ERROR_ALREADY_INITIALIZED,
    MH_ERROR_NOT_INITIALIZED,
    MH_ERROR_ALREADY_CREATED,
    MH_ERROR_NOT_CREATED,
    MH_ERROR_ENABLED,
    MH_ERROR_DISABLED,
    MH_ERROR_NOT_EXECUTABLE,
    MH_ERROR_UNSUPPORTED_FUNCTION,
    MH_ERROR_MEMORY_ALLOC,
    MH_ERROR_MEMORY_PROTECT,
    MH_ERROR_MODULE_NOT_FOUND,
    MH_ERROR_FUNCTION_NOT_FOUND
}
MH_STATUS;

#define MEMORY_SLOT_SIZE 64

#pragma pack(push, 1)

typedef struct _JMP_REL_SHORT
{
    uint8_t  opcode;
    uint8_t  operand;
} JMP_REL_SHORT, * PJMP_REL_SHORT;

typedef struct _JMP_REL
{
    uint8_t  opcode;
    uint32_t operand;
} JMP_REL, * PJMP_REL, CALL_REL;

typedef struct _JMP_ABS
{
    uint8_t  opcode0;
    uint8_t  opcode1;
    uint32_t dummy;
    uint64_t address;     // Absolute destination address
} JMP_ABS, * PJMP_ABS;

// 64-bit indirect absolute call.
typedef struct _CALL_ABS
{
    uint8_t  opcode0;     // FF15 00000002: CALL [+6]
    uint8_t  opcode1;
    uint32_t dummy0;
    uint8_t  dummy1;      // EB 08:         JMP +10
    uint8_t  dummy2;
    uint64_t address;     // Absolute destination address
} CALL_ABS;

// 32-bit direct relative conditional jumps.
typedef struct _JCC_REL
{
    uint8_t  opcode0;     // 0F8* xxxxxxxx: J** +6+xxxxxxxx
    uint8_t  opcode1;
    uint32_t operand;     // Relative destination address
} JCC_REL;

// 64bit indirect absolute conditional jumps that x64 lacks.
typedef struct _JCC_ABS
{
    uint8_t  opcode;      // 7* 0E:         J** +16
    uint8_t  dummy0;
    uint8_t  dummy1;      // FF25 00000000: JMP [+6]
    uint8_t  dummy2;
    uint32_t dummy3;
    uint64_t address;     // Absolute destination address
} JCC_ABS;

#pragma pack(pop)

typedef struct _TRAMPOLINE
{
    LPVOID pTarget;         // [In] Address of the target function.
    LPVOID pDetour;         // [In] Address of the detour function.
    LPVOID pTrampoline;     // [In] Buffer address for the trampoline and relay function.
    LPVOID pRelay;
    BOOL   patchAbove;      // [Out] Should use the hot patch area?
    UINT   nIP;             // [Out] Number of the instruction boundaries.
    uint8_t  oldIPs[8];       // [Out] Instruction boundaries of the target function.
    uint8_t  newIPs[8];       // [Out] Instruction boundaries of the trampoline function.
} TRAMPOLINE, * PTRAMPOLINE;

typedef struct _HOOK_ENTRY
{
    LPVOID pTarget;             // Address of the target function.
    LPVOID pDetour;             // Address of the detour or relay function.
    LPVOID pTrampoline;         // Address of the trampoline function.
    uint8_t  backup[8];           // Original prologue of the target function.

    uint8_t  patchAbove : 1;     // Uses the hot patch area.
    uint8_t  isEnabled : 1;     // Enabled.

    UINT   nIP : 4;             // Count of the instruction boundaries.
    uint8_t  oldIPs[8];           // Instruction boundaries of the target function.
    uint8_t  newIPs[8];           // Instruction boundaries of the trampoline function.
} HOOK_ENTRY, * PHOOK_ENTRY;



namespace hooking
{
    namespace minhook
    {
        VOID   mh_buffer_destroy(VOID);
        LPVOID mh_buffer_allocate(LPVOID pOrigin);
        __declspec(noinline) VOID   mh_buffer_free(LPVOID pBuffer);
        __declspec(noinline) BOOL   mh_buffer_is_executable_address(LPVOID pAddress);

        __declspec(noinline) BOOL create_trampoline_function(PTRAMPOLINE ct);

        __declspec(noinline) MH_STATUS mh_destroy(VOID);
        __declspec(noinline) MH_STATUS mh_create_hook(LPVOID pTarget, LPVOID pDetour, LPVOID* ppOriginal);

        __declspec(noinline) MH_STATUS mh_remove_hook(LPVOID pTarget);

        __declspec(noinline) MH_STATUS  enable_hook_ex(LPVOID pTarget, BOOL enable);

        __forceinline MH_STATUS mh_enable_hook(LPVOID pTarget)
        {
            return enable_hook_ex(pTarget, TRUE);
        }

        __forceinline MH_STATUS mh_disable_hook(LPVOID pTarget)
        {
            return enable_hook_ex(pTarget, FALSE);
        }

        __declspec(noinline) PHOOK_ENTRY get_hook_entry(LPVOID pTarget);
    }
}




