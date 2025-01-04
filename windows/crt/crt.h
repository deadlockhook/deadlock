#pragma once

#include "../typedefs.h"
#include <Windows.h>
#include <type_traits>

__forceinline int to_lower(char c) {
    if (c >= 'A' && c <= 'Z') {
        return c + ('a' - 'A');
    }
    return c;
}

__forceinline int _strlen(const char* string)
{
    int cnt = 0;
    if (string)
    {
        for (; *string != 0; ++string) ++cnt;
    }
    return cnt;
}

inline int _strcmp(const char* cs, const char* ct, _bool CaseSensitive = true)
{
    if (cs && ct)
    {
        if (CaseSensitive) {
            while (*cs == *ct)
            {
                if (*cs == 0 && *ct == 0)
                    return 0;

                if (*cs == 0 || *ct == 0)
                    break;

                cs++;
                ct++;
            }

            return *cs - *ct;
        }
        else {

            while (to_lower(*cs) == to_lower(*ct)) {

                if (*cs == 0 && *ct == 0)
                    return 0;

                if (*cs == 0 || *ct == 0)
                    break;

                cs++;
                ct++;
            }

            return to_lower(*cs) - to_lower(*ct);
        }
    }

    return -1;
}

__forceinline int _strcmp_cmplen(const char* cs, const char* ct, _bool CaseSensitive = true)
{
    if (_strlen(cs) != _strlen(ct))
        return -1;

    return _strcmp(cs, ct, CaseSensitive);
}

__forceinline wchar_t to_lower_wide(wchar_t wc) {
    if (wc >= L'A' && wc <= L'Z') {
        return wc + (L'a' - L'A');
    }
    return wc;
}

__forceinline int _wcslen(const wchar_t* s)
{
    int cnt = 0;
    if (!s)
        return 0;

    for (; *s != L'\0'; ++s) ++cnt;

    return cnt;
}

inline int _wcscmp(const wchar_t* cs, const wchar_t* ct, _bool CaseSensitive = true)
{
    if (cs && ct)
    {
        if (CaseSensitive) {
            while (*cs == *ct)
            {
                if (*cs == 0 && *ct == 0) return 0;
                if (*cs == 0 || *ct == 0) break;
                cs++;
                ct++;
            }
            return *cs - *ct;
        }
        else
        {
            while (to_lower_wide(*cs) == to_lower_wide(*ct)) {

                if (*cs == 0 && *ct == 0)
                    return 0;

                if (*cs == 0 || *ct == 0)
                    break;

                cs++;
                ct++;
            }

            return to_lower_wide(*cs) - to_lower_wide(*ct);
        }
    }
    return -1;
}


__forceinline bool in_range(unsigned long long value, unsigned long long low_value, unsigned long long high_value) {

    if (value >= low_value && value < high_value)
        return true;

    return false;
}

template <class t = void*, class t2 = void*>
__forceinline void _memcpy(t dest, t2 src, unsigned long long size)
{
    if (!dest || !src || size <= 0)
        return;

    __movsb((PBYTE)dest, (BYTE*)src, (SIZE_T)size);

  //  memcpy((char*)dest, (char*)src, size);
}

template <class t = void*>
__forceinline void _memset(t dest, char value, unsigned long long size) {

    if (!dest || size <= 0)
        return;

    memset((char*)dest, value, size);
}

template <class t = void*>
__forceinline bool _memequal(t left, t right, unsigned long long size) {

    if (!left && !right)
        return true;

    if ((!left && right) || (left && !right))
        return false;

    return memcmp((char*)left, (char*)right, size) == 0;
}

__forceinline void min_max(int& value, int min, int max) {
    if (value < min)
        value = min;

    if (value > max)
        value = max;
}

template <class t = void*>
__forceinline void _zeromemory(t dest, unsigned long long size)
{
    _memset(dest, 0, size);
}

template <class t>
struct remove_reference {
    using type = t;
    using _Const_thru_ref_type = const t;
};

template <class t>
_NODISCARD constexpr std::remove_reference_t<t>&& _move(t&& _Arg) noexcept {
    return static_cast<std::remove_reference_t<t>&&>(_Arg);
}

inline void reverse_string(char* str, int length) {
    int start = 0;
    int end = length - 1;
    while (start < end) {
        char temp = str[start];
        str[start] = str[end];
        str[end] = temp;
        start++;
        end--;
    }
}

inline char* to_string(int num, char* str, int base = 10) {
    int i = 0;
    bool isNegative = false;

    if (num == 0) {
        str[i++] = '0';
        str[i] = '\0';
        return str;
    }

    if (num < 0 && base == 10) {
        isNegative = true;
        num = -num;
    }

    while (num != 0) {
        int rem = num % base;
        str[i++] = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
        num = num / base;
    }

    if (isNegative) {
        str[i++] = '-';
    }

    str[i] = '\0';

    reverse_string(str, i);

    return str;
}

