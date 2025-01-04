#pragma once
#include "../typedefs.h"

namespace random
{
    template <class T>
    static __forceinline void generate_random_bytes(T* byteArray, _ulong sizeOfBytes) {

        if (byteArray && sizeOfBytes > 0)
            execute_call<NTSTATUS>(windows::api::bcrypt::BCryptGenRandom, nullptr, byteArray, (_ulong)sizeOfBytes, (_ulong)BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    }

    template <class T = _ulonglong>
    static __forceinline T generate_random_bytes() {

        T byteArray = {};

        generate_random_bytes(&byteArray, sizeof(byteArray));
        return byteArray;
    }
}