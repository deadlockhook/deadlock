#pragma once

#include "md5.h"
#include <DbgHelp.h>

namespace pdb_parser
{
	typedef struct _pdb_path_info
	{
		HANDLE process_handle;
		HANDLE file_handle;
		secure_string pdb_path;
		~_pdb_path_info();
	}pdb_path_info, * ppdb_path_info;

	ppdb_path_info download_and_load_pdb_from_system32_directory(const char* file_name); 
	ppdb_path_info download_and_load_pdb(const secure_wide_string& file_path);
	unsigned int get_rva(ppdb_path_info pdb_info, const char* symbol_name);
	unsigned int get_struct_variable_offset(ppdb_path_info pdb_info, const char* structure_name, const wchar_t* variable_name);
	void unload_and_delete_pdb(ppdb_path_info pdb_info);
}
