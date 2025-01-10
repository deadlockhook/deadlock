#pragma once

#include "../common.h"
#include "../winapi/wrapper.h"


namespace memory
{
	inline HANDLE heap = INVALID_HANDLE_VALUE;
	template<class t>
	__forceinline t* new_class()
	{
		return new t();
	}

	template<class t>
	__forceinline void delete_class(t** ptr)
	{
		if (ptr && *ptr) {
			delete (*ptr);
			*ptr = nullptr;
		}
	}

	template<class t>
	__forceinline void delete_class(t* ptr)
	{
		if (ptr)
			delete ptr;
	}

	__forceinline _bool_enc initialize() {

		ULONG flags = HEAP_GROWABLE;
		SIZE_T reserveSize = 0;
		SIZE_T commitSize = 0;
		PVOID heapBase = NULL;
		PVOID lock = NULL;

		typedef struct _RTL_HEAP_PARAMETERS {
			ULONG                    Length;
			SIZE_T                   SegmentReserve;
			SIZE_T                   SegmentCommit;
			SIZE_T                   DeCommitFreeBlockThreshold;
			SIZE_T                   DeCommitTotalFreeThreshold;
			SIZE_T                   MaximumAllocationSize;
			SIZE_T                   VirtualMemoryThreshold;
			SIZE_T                   InitialCommit;
			SIZE_T                   InitialReserve;
			PVOID                    CommitRoutine;
			SIZE_T                   Reserved[2];
		} RTL_HEAP_PARAMETERS, * PRTL_HEAP_PARAMETERS;

		RTL_HEAP_PARAMETERS heapParams;
		_zeromemory(&heapParams, sizeof(heapParams));

		heap = execute_call<HANDLE>(windows::api::ntdll::RtlCreateHeap, flags, heapBase, reserveSize, commitSize, lock, &heapParams);
		return heap != nullptr;
	}

	__forceinline _bool_enc _write_virtual_memory(encryption::encrypted_block<HANDLE> process_handle, _pvoid_enc target, _pvoid_enc buffer, _ulonglong_enc size) {
		SIZE_T bytes_written;
		return execute_call<BOOL>(windows::api::kernel32::WriteProcessMemory, process_handle.get_decrypted(), target.get_decrypted(), buffer.get_decrypted(), (SIZE_T)size.get_decrypted(), &bytes_written);
	}

	__forceinline _bool_enc _read_virtual_memory(encryption::encrypted_block<HANDLE> process_handle, _pvoid_enc target, _pvoid_enc buffer, _ulonglong_enc size) {
		SIZE_T bytes_read;
		return execute_call<BOOL>(windows::api::kernel32::ReadProcessMemory, process_handle.get_decrypted(), target.get_decrypted(), buffer.get_decrypted(), (SIZE_T)size.get_decrypted(), &bytes_read);
	}

	__forceinline _pvoid_enc _virtual_alloc(_ulonglong_enc size, _uint_enc Protection = PAGE_READWRITE, _uint_enc AllocationType = MEM_COMMIT | MEM_RESERVE) {
		return 	execute_call<void*>(windows::api::kernel32::VirtualAlloc, (LPVOID)nullptr, size.get_decrypted(), AllocationType.get_decrypted(), Protection.get_decrypted());
	}

	__forceinline _bool_enc query_virtual_memory(_pvoid_enc address, encryption::encrypted_block<MEMORY_BASIC_INFORMATION>& out) {
		MEMORY_BASIC_INFORMATION mbi;
		_bool_enc ret = execute_call<BOOL>(windows::api::kernel32::VirtualQuery, address.get_decrypted(), &mbi, sizeof(mbi));
		out = mbi;
		return ret;
	}
	__forceinline _bool_enc _virtual_protect(_pvoid_enc base, _ulonglong_enc size, _uint_enc Protection, PDWORD old_protection) {
		return 	execute_call<BOOL>(windows::api::kernel32::VirtualProtect, (LPVOID)base.get_decrypted(), (SIZE_T)size.get_decrypted(), (DWORD)Protection.get_decrypted(), old_protection);
	}

	__forceinline _pvoid_enc _virtual_free(_pvoid_enc base) {
		return 	execute_call<void*>(windows::api::kernel32::VirtualFree, base.get_decrypted(), (SIZE_T)0, MEM_RELEASE);
	}

	__forceinline _pvoid_enc _malloc(_ulonglong_enc size) {
		return execute_call<void*>(windows::api::ntdll::RtlAllocateHeap, heap, HEAP_ZERO_MEMORY, size.get_decrypted());
	}

	__forceinline _pvoid_enc _realloc(_pvoid_enc adr, _ulonglong_enc size) {
		return execute_call<void*>(windows::api::ntdll::RtlReAllocateHeap, heap, 0, adr.get_decrypted(), size.get_decrypted());
	}

	__forceinline void _free(_pvoid_enc adr) {
		execute_call<BOOL>(windows::api::ntdll::RtlFreeHeap, heap, 0, adr.get_decrypted());
	}
}


