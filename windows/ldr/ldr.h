#pragma once

#include "../winapi/wrapper.h"

namespace ldr
{
	_pvoid_enc load_library_ex(_pvoid_enc src_data, _bool_enc clear_header, _bool_enc clear_non_needed_sections, _bool_enc adjust_protections, _bool_enc seh_exception_support, _int_enc reason, _pvoid_enc reserved, uintptr_t* seh_function_table_entries);
	_pvoid_enc load_library(_pvoid_enc src_data, _pvoid_enc reserved = nullptr, uintptr_t* seh_function_table_entries = nullptr);
	void unload_library(_pvoid_enc base);

	namespace remote
	{
		_pvoid_enc load_library_ex(HANDLE process_handle, _pvoid_enc src_data, _bool_enc clear_header, _bool_enc clear_non_needed_sections, _bool_enc adjust_protections, _bool_enc seh_exception_support, _int_enc reason, _pvoid_enc reserved);
		_pvoid_enc load_library(HANDLE process_handle, DWORD process_id, _pvoid_enc src_data, _pvoid_enc reserved);
		void unload_library(HANDLE process_handle, DWORD process_id, _pvoid_enc base);
	}
}