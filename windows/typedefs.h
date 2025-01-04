#pragma once 
#include <Windows.h>
#include <type_traits>

typedef char _char;
typedef wchar_t _wchar;
typedef bool _bool;
typedef short _short;
typedef int _int;
typedef long _long;
typedef long long _longlong;

typedef unsigned char _uchar;
typedef unsigned short _ushort;
typedef unsigned int _uint;
typedef unsigned long _ulong;
typedef unsigned long long _ulonglong;

typedef signed char _schar;
typedef signed short _sshort;
typedef signed int _sint;
typedef signed long _slong;
typedef signed long long _slonglong;

template<class _Ty>
using clean_type = typename std::remove_const_t<std::remove_reference_t<_Ty>>;

#define IS_VALID_HANDLE(handle)				(handle && handle != INVALID_HANDLE_VALUE)
#define NT_GLOBAL_FLAG_DEBUGGED (0x70)
#define DEBUG_OBJECT_KILLONCLOSE	0x1
#define DEBUG_READ_EVENT			0x0001
#define DEBUG_PROCESS_ASSIGN		0x0002
#define DEBUG_SET_INFORMATION		0x0004
#define DEBUG_QUERY_INFORMATION		0x0008
#define DEBUG_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE |  DEBUG_READ_EVENT | DEBUG_PROCESS_ASSIGN | DEBUG_SET_INFORMATION | DEBUG_QUERY_INFORMATION)

#define STATUS_PORT_NOT_SET					((NTSTATUS)0xC0000353L)

#define PDI_MODULES                       0x01
#define PDI_BACKTRACE                     0x02
#define PDI_HEAPS                         0x04
#define PDI_HEAP_TAGS                     0x08
#define PDI_HEAP_BLOCKS                   0x10
#define PDI_LOCKS                         0x20

#define NtCurrentProcess() ((HANDLE)-1)

#define PAGE_SIZE 0x1000
