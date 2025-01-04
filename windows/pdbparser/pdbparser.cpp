#include "pdbparser.h"
#include "../winapi/wrapper.h"
#include "../filesystem/filesystem.h"
#include "../memory/memory.h"

using namespace windows;

pdb_parser::pdb_path_info::~_pdb_path_info() {
	execute_call(windows::api::Dbghelp::SymUnloadModule64, process_handle, (DWORD64)0x10000000);
	execute_call(windows::api::Dbghelp::SymCleanup, process_handle);
	execute_call(windows::api::kernel32::CloseHandle, process_handle);
	execute_call(windows::api::kernel32::CloseHandle, file_handle);

	if (pdb_path.size()) {
		windows::api::securely_delete_file(windows::api::multibyte_to_unicode(pdb_path.c_str()));
		execute_call(windows::api::kernel32::DeleteFileA, pdb_path.c_str());
		pdb_path.clear_secure();
	}
}
pdb_parser::ppdb_path_info pdb_parser::download_and_load_pdb_from_system32_directory(const char* file_name) {
	return pdb_parser::download_and_load_pdb(windows::api::multibyte_to_unicode(windows::api::get_file_path_in_system32(file_name).c_str()));
}

pdb_parser::ppdb_path_info pdb_parser::download_and_load_pdb(const secure_wide_string& file_path) {

//	vm_mutate_start

		if (!file_path.size())
			return nullptr;

	auto pdb_download_path = windows::api::get_environment_variable((PCHAR)ENCRYPT_STRING("LOCALAPPDATA"));

	if (!pdb_download_path.size())
		return nullptr;

	if (pdb_download_path[pdb_download_path.length() - 1] != '\\')
		pdb_download_path += (PCHAR)ENCRYPT_STRING("\\");

	auto file_size = filesystem::get_file_size(file_path.c_str()).get_decrypted();

	if (!file_size)
		return nullptr;

	auto file_data = filesystem::read_file(file_path.c_str()).get_decrypted();

	if (!file_data)
		return nullptr;

	pdb_download_path += md5(file_data, (ULONG)file_size).c_str();
	pdb_download_path += (PCHAR)ENCRYPT_STRING(".pdb");

	windows::api::securely_delete_file(windows::api::multibyte_to_unicode(pdb_download_path.c_str()));

	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)file_data;
	IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)((uintptr_t)file_data + dos_header->e_lfanew);
	IMAGE_FILE_HEADER* file_header = &nt_header->FileHeader;
	IMAGE_OPTIONAL_HEADER64* optional_header_64 = NULL;
	IMAGE_OPTIONAL_HEADER32* optional_header_32 = NULL;
	BOOL x86 = FALSE;
	if (file_header->Machine == IMAGE_FILE_MACHINE_AMD64)
		optional_header_64 = (IMAGE_OPTIONAL_HEADER64*)(&nt_header->OptionalHeader);
	else if (file_header->Machine == IMAGE_FILE_MACHINE_I386)
	{
		optional_header_32 = (IMAGE_OPTIONAL_HEADER32*)(&nt_header->OptionalHeader);
		x86 = TRUE;
	}
	else
	{
		memory::_free(file_data);
		return nullptr;
	}

	DWORD image_size = x86 ? optional_header_32->SizeOfImage : optional_header_64->SizeOfImage;
	PBYTE image_buffer = (PBYTE)memory::_malloc((unsigned long long)image_size).get_decrypted();

	if (!image_buffer) {
		memory::_free(file_data);
		return nullptr;
	}

	memcpy(image_buffer, file_data, x86 ? optional_header_32->SizeOfHeaders : optional_header_64->SizeOfHeaders);

	IMAGE_SECTION_HEADER* pCurrentSectionHeader = IMAGE_FIRST_SECTION(nt_header);
	for (UINT i = 0; i != file_header->NumberOfSections; ++i, ++pCurrentSectionHeader)
		if (pCurrentSectionHeader->SizeOfRawData)
			memcpy(image_buffer + pCurrentSectionHeader->VirtualAddress, (void*)((uintptr_t)file_data + pCurrentSectionHeader->PointerToRawData), pCurrentSectionHeader->SizeOfRawData);

	IMAGE_DATA_DIRECTORY* pDataDir = nullptr;

	if (x86)
		pDataDir = &optional_header_32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	else
		pDataDir = &optional_header_64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

	IMAGE_DEBUG_DIRECTORY* pDebugDir = (IMAGE_DEBUG_DIRECTORY*)(image_buffer + pDataDir->VirtualAddress);
	if (!pDataDir->Size || IMAGE_DEBUG_TYPE_CODEVIEW != pDebugDir->Type)
	{
		memory::_free(file_data);
		memory::_free(image_buffer);
		return nullptr;
	}

	struct PdbInfo
	{
		DWORD	Signature;
		GUID	Guid;
		DWORD	Age;
		char	PdbFileName[1];
	};

	PdbInfo* pdb_info = (PdbInfo*)(image_buffer + pDebugDir->AddressOfRawData);
	if (pdb_info->Signature != 0x53445352)
	{
		memory::_free(file_data);
		memory::_free(image_buffer);
		return nullptr;
	}

	char szGUID[256] = { 0 };
	windows::api::string_from_guid2(pdb_info->Guid, szGUID);

	size_t sizeGuid = _strlen(szGUID);

	if (!sizeGuid) {
		memory::_free(file_data);
		memory::_free(image_buffer);
		return nullptr;
	}

	char GUID_Filtered[256] = { 0 };
	for (UINT i = 0; i != sizeGuid; ++i)
		if ((szGUID[i] >= '0' && szGUID[i] <= '9') || (szGUID[i] >= 'A' && szGUID[i] <= 'F') || (szGUID[i] >= 'a' && szGUID[i] <= 'f'))
			GUID_Filtered[_strlen(GUID_Filtered)] = szGUID[i];


	char Age[3] = { 0 };
	_itoa_s(pdb_info->Age, Age, 10);

	secure_string symbol_url = (PCHAR)ENCRYPT_STRING("https://msdl.microsoft.com/download/symbols/");
	symbol_url += pdb_info->PdbFileName;
	symbol_url += "/";
	symbol_url += GUID_Filtered;
	symbol_url += Age;
	symbol_url += "/";
	symbol_url += pdb_info->PdbFileName;

	memory::_free(file_data);
	memory::_free(image_buffer);

	HRESULT hr = execute_call<HRESULT>(api::Urlmon::URLDownloadToFileA, (LPUNKNOWN)nullptr, symbol_url.c_str(), pdb_download_path.c_str(), NULL, (LPBINDSTATUSCALLBACK)nullptr);

	if (FAILED(hr))
		return nullptr;

	//if (!net::net_download_file_to_disk(symbol_url, pdb_download_path).get_decrypted())
	//	return nullptr;

	WIN32_FILE_ATTRIBUTE_DATA file_attr_data{ 0 };

	if (!execute_call<HANDLE>(api::kernel32::GetFileAttributesExA, pdb_download_path.c_str(), (GET_FILEEX_INFO_LEVELS)GetFileExInfoStandard, &file_attr_data))
		return nullptr;

	auto pdbSize = file_attr_data.nFileSizeLow;

	HANDLE hPdbFile = execute_call<HANDLE>(api::kernel32::CreateFileA, (LPCSTR)pdb_download_path.c_str(), GENERIC_READ, FILE_SHARE_READ, (LPSECURITY_ATTRIBUTES)NULL, OPEN_EXISTING, NULL, (HANDLE)NULL);

	if (hPdbFile == INVALID_HANDLE_VALUE)
		return nullptr;

	HANDLE hProcess = execute_call<HANDLE>(api::kernel32::OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, (BOOL)FALSE, GetCurrentProcessId());

	if (!hProcess)
	{
		execute_call(api::kernel32::CloseHandle, hPdbFile);
		return nullptr;
	}

	if (!execute_call<BOOL>(api::Dbghelp::SymInitialize, hProcess, pdb_download_path.c_str(), (BOOL)FALSE))
	{
		execute_call(api::kernel32::CloseHandle, hProcess);
		execute_call(api::kernel32::CloseHandle, hPdbFile);
		return nullptr;
	}

	execute_call<DWORD>(api::Dbghelp::SymSetOptions, SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_AUTO_PUBLICS | SYMOPT_DEBUG | SYMOPT_LOAD_ANYTHING);

	DWORD64 SymbolTable = execute_call<DWORD64>(api::Dbghelp::SymLoadModuleEx, (HANDLE)hProcess, (HANDLE)NULL, pdb_download_path.c_str(), NULL, (DWORD64)0x10000000, pdbSize, (PMODLOAD_DATA)NULL, NULL);

	if (!SymbolTable)
	{
		execute_call(api::Dbghelp::SymCleanup, hProcess);
		execute_call(api::kernel32::CloseHandle, hProcess);
		execute_call(api::kernel32::CloseHandle, hPdbFile);
		return nullptr;
	}

	//vm_mutate_end

    return new pdb_path_info{ hProcess, hPdbFile ,pdb_download_path.c_str() };
}

void pdb_parser::unload_and_delete_pdb(ppdb_path_info pdb_info) {


	delete pdb_info;
}

unsigned int pdb_parser::get_rva(ppdb_path_info pdb_info, const char* symbol_name) {
	SYMBOL_INFO si = { 0 };
	si.SizeOfStruct = sizeof(SYMBOL_INFO);

	if (!execute_call<BOOL>(api::Dbghelp::SymFromName, pdb_info->process_handle, symbol_name, &si))
		return 0;

	return (ULONG)(si.Address - si.ModBase);
}

unsigned int pdb_parser::get_struct_variable_offset(ppdb_path_info pdb_info, const char* structure_name, const wchar_t* variable_name)
{
	ULONG SymInfoSize = sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR);
	SYMBOL_INFO* SymInfo = (SYMBOL_INFO*)memory::_malloc((_ulonglong)SymInfoSize).get_decrypted();
	if (!SymInfo)
	{
		return  (ULONG)-1;
	}

	_zeromemory(SymInfo, SymInfoSize);
	SymInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
	SymInfo->MaxNameLen = MAX_SYM_NAME;

	if (!execute_call<BOOL>(api::Dbghelp::SymGetTypeFromName, pdb_info->process_handle, 0x10000000, structure_name, SymInfo))
	{
		return  (ULONG)-1;
	}

	TI_FINDCHILDREN_PARAMS TempFp = { 0 };
	if (!execute_call<BOOL>(api::Dbghelp::SymGetTypeInfo, pdb_info->process_handle, 0x10000000, SymInfo->TypeIndex, TI_GET_CHILDRENCOUNT, &TempFp))
	{
		memory::_free(SymInfo);
		return  (ULONG)-1;
	}

	ULONG ChildParamsSize = sizeof(TI_FINDCHILDREN_PARAMS) + TempFp.Count * sizeof(ULONG);
	TI_FINDCHILDREN_PARAMS* ChildParams = (TI_FINDCHILDREN_PARAMS*)memory::_malloc(ChildParamsSize).get_decrypted();
	if (ChildParams == NULL)
	{
		memory::_free(SymInfo);
		return (ULONG)-1;
	}

	_zeromemory(ChildParams, ChildParamsSize);
	_memcpy(ChildParams, &TempFp, sizeof(TI_FINDCHILDREN_PARAMS));

	if (!execute_call<BOOL>(api::Dbghelp::SymGetTypeInfo, pdb_info->process_handle, 0x10000000, SymInfo->TypeIndex, TI_FINDCHILDREN, ChildParams))
	{
		goto failed;
	}
	for (ULONG i = ChildParams->Start; i < ChildParams->Count; i++)
	{
		WCHAR* pSymName = NULL;
		ULONG Offset = 0;
		if (!execute_call<BOOL>(api::Dbghelp::SymGetTypeInfo, pdb_info->process_handle, 0x10000000, ChildParams->ChildId[i], TI_GET_OFFSET, &Offset))
		{
			goto failed;
		}
		if (!execute_call<BOOL>(api::Dbghelp::SymGetTypeInfo, pdb_info->process_handle, 0x10000000, ChildParams->ChildId[i], TI_GET_SYMNAME, &pSymName))
		{
			goto failed;
		}
		if (pSymName)
		{

			if (wcscmp(pSymName, variable_name) == 0)
			{
				execute_call<BOOL>(api::kernel32::LocalFree, pSymName);
				memory::_free(ChildParams);
				memory::_free(SymInfo);
				return Offset;
			}
		}
	}
failed:
	memory::_free(ChildParams);
	memory::_free(SymInfo);
	return  (ULONG)-1;
}
