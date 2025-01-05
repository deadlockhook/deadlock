#include "ldr.h"
#include "../memory/memory.h"

using namespace windows;

__declspec(noinline) bool call_entry_point_safe(void* entry_point, void* target_base, DWORD reason, void* reserved) {

	bool ret = true;

	__try {

		auto _DllMain = reinterpret_cast<BOOL(WINAPI*)(void*, DWORD, void*)>(entry_point);
		_DllMain(target_base, reason, reserved);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ret = false;
	}

	return ret;

}
_pvoid_enc ldr::load_library_ex(_pvoid_enc src_data, _bool_enc clear_header, _bool_enc clear_non_needed_sections, _bool_enc adjust_protections, _bool_enc seh_exception_support, _int_enc reason, _pvoid_enc reserved, uintptr_t* seh_function_table_entries) {

	unsigned char* src_data_dcr = (unsigned char*)src_data.get_decrypted();

	IMAGE_NT_HEADERS* pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(src_data_dcr + reinterpret_cast<IMAGE_DOS_HEADER*>(src_data_dcr)->e_lfanew);
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = &pOldNtHeader->OptionalHeader;
	IMAGE_FILE_HEADER* pOldFileHeader = &pOldNtHeader->FileHeader;

	unsigned char* target_base = (unsigned char*)memory::_virtual_alloc((unsigned long long)pOldOptHeader->SizeOfImage, PAGE_EXECUTE_READWRITE).get_decrypted();

	if (!target_base)
		return nullptr;

	DWORD oldp = 0;

	_memcpy(target_base, src_data_dcr, 0x1000);

	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);

	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
		if (pSectionHeader->SizeOfRawData)
			_memcpy(target_base + pSectionHeader->VirtualAddress, src_data_dcr + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData);

	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(target_base + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)target_base)->e_lfanew)->OptionalHeader;

	BYTE* LocationDelta = target_base - pOpt->ImageBase;
	if (LocationDelta) {
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(target_base + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					if (((*pRelativeInfo) >> 0x0C) == IMAGE_REL_BASED_DIR64) {
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(target_base + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(target_base + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name) {
			char* szMod = reinterpret_cast<char*>(target_base + pImportDescr->Name);
			HINSTANCE hDll = execute_call<HINSTANCE>(api::kernel32::LoadLibraryA, szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(target_base + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(target_base + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = (ULONG_PTR)execute_call<FARPROC>(api::kernel32::GetProcAddress, hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else {
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(target_base + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)execute_call<FARPROC>(api::kernel32::GetProcAddress, hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(target_base + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(target_base, DLL_PROCESS_ATTACH, nullptr);
	}

	auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (excep.Size) {
		if (!RtlAddFunctionTable(
			reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(target_base + excep.VirtualAddress),
			excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)target_base)) {

		}
		else if (seh_function_table_entries)
			*seh_function_table_entries = reinterpret_cast<uintptr_t>(target_base + excep.VirtualAddress);
	}


	if (!call_entry_point_safe((void*)(target_base + pOpt->AddressOfEntryPoint), target_base, reason.get_decrypted(), reserved.get_decrypted())) {
		memory::_virtual_free(target_base);
		return nullptr;
	}

	if (clear_header.get_decrypted())
		_zeromemory(target_base, 0x1000);

	if (clear_non_needed_sections.get_decrypted()) {
		pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
			if (pSectionHeader->Misc.VirtualSize) {
				if ((seh_exception_support.get_decrypted() ? 0 : _strcmp((char*)pSectionHeader->Name, (PCHAR)ENCRYPT_STRING(".pdata")) == 0) ||
					_strcmp((char*)pSectionHeader->Name, (PCHAR)ENCRYPT_STRING(".rsrc")) == 0 ||
					_strcmp((char*)pSectionHeader->Name, (PCHAR)ENCRYPT_STRING(".reloc")) == 0) {
					_zeromemory(target_base + pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize);
				}
			}
		}
	}

	if (adjust_protections.get_decrypted()) {

		pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);

		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
			if (pSectionHeader->Misc.VirtualSize) {
				DWORD old = 0;
				DWORD newP = PAGE_READONLY;

				if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) > 0)
					newP = PAGE_READWRITE;
				else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0)
					newP = PAGE_EXECUTE_READ;

				memory::_virtual_protect(target_base + pSectionHeader->VirtualAddress, (unsigned long long)pSectionHeader->Misc.VirtualSize, newP, &old);
			}
		}

		DWORD old = 0;
		memory::_virtual_protect(target_base, (unsigned long long)IMAGE_FIRST_SECTION(pOldNtHeader)->VirtualAddress, PAGE_READONLY, &old);

	}

	return target_base;

}

_pvoid_enc ldr::load_library(_pvoid_enc src_data, _pvoid_enc reserved, uintptr_t* seh_function_table_entries) {
	return load_library_ex(src_data, TRUE, TRUE, FALSE, TRUE, DLL_PROCESS_ATTACH, reserved, seh_function_table_entries);
}

void ldr::unload_library(_pvoid_enc base) {
	memory::_virtual_free(base);
}

struct manual_mapping_data
{
	decltype(&LoadLibraryA) LoadLibraryA;
	decltype(&GetProcAddress) GetProcAddress;
	decltype(&RtlAddFunctionTable) RtlAddFunctionTable;
	BYTE* pbase;
	HINSTANCE hMod;
	DWORD fdwReasonParam;
	LPVOID reservedParam;
	BOOL SEHSupport;
};

void __stdcall remote_shellcode(manual_mapping_data* mapping_data);

_pvoid_enc  ldr::remote::load_library_ex(HANDLE process_handle, _pvoid_enc src_data, _bool_enc clear_header, _bool_enc clear_non_needed_sections, _bool_enc adjust_protections, _bool_enc seh_exception_support, _int_enc reason, _pvoid_enc reserved) {
	unsigned char* src_data_dcr = (unsigned char*)src_data.get_decrypted();

	IMAGE_NT_HEADERS* pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(src_data_dcr + reinterpret_cast<IMAGE_DOS_HEADER*>(src_data_dcr)->e_lfanew);
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = &pOldNtHeader->OptionalHeader;
	IMAGE_FILE_HEADER* pOldFileHeader = &pOldNtHeader->FileHeader;

	unsigned char* target_base = (unsigned char*)execute_call<void*>(api::kernel32::VirtualAllocEx, process_handle, (LPVOID)nullptr, (unsigned long long)pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!target_base)
		return nullptr;

	memory::_write_virtual_memory(process_handle, target_base, src_data_dcr, (unsigned long long)0x1000);

	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);

	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
		if (pSectionHeader->SizeOfRawData)
			memory::_write_virtual_memory(process_handle, target_base + pSectionHeader->VirtualAddress, src_data_dcr + pSectionHeader->PointerToRawData, (unsigned long long)pSectionHeader->SizeOfRawData);

	manual_mapping_data data{ 0 };
	data.LoadLibraryA = (decltype(&LoadLibraryA))api::kernel32::LoadLibraryA.get_decrypted();
	data.GetProcAddress = (decltype(&GetProcAddress))api::kernel32::GetProcAddress.get_decrypted();
	data.RtlAddFunctionTable = &RtlAddFunctionTable;
	data.pbase = target_base;
	data.fdwReasonParam = reason.get_decrypted();
	data.reservedParam = reserved.get_decrypted();
	data.SEHSupport = seh_exception_support.get_decrypted();

	unsigned char* mapping_data_allocated = (unsigned char*)execute_call<void*>(api::kernel32::VirtualAllocEx, process_handle, (LPVOID)nullptr, (unsigned long long)sizeof(manual_mapping_data), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memory::_write_virtual_memory(process_handle, mapping_data_allocated, &data, sizeof(manual_mapping_data));

	void* shellcode = (unsigned char*)execute_call<void*>(api::kernel32::VirtualAllocEx, process_handle, (LPVOID)nullptr, (unsigned long long)0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	memory::_write_virtual_memory(process_handle, shellcode, remote_shellcode, 0x1000);

	HANDLE hThread = execute_call<HANDLE>(api::kernel32::CreateRemoteThread, process_handle, nullptr, (SIZE_T)0, reinterpret_cast<LPTHREAD_START_ROUTINE>(shellcode), mapping_data_allocated, 0, nullptr);

	HINSTANCE hCheck = NULL;

	int tries = 1000;

	while (!hCheck && tries > 0) {
		DWORD exitcode = 0;
		execute_call<HANDLE>(api::kernel32::GetExitCodeProcess, process_handle, &exitcode);

		if (exitcode != STILL_ACTIVE)
			return nullptr;

		manual_mapping_data data_checked{ 0 };
		memory::_read_virtual_memory(process_handle, mapping_data_allocated, &data_checked, sizeof(data_checked));

		hCheck = data_checked.hMod;
		Sleep(10);
		--tries;
	}

	if (!hCheck)
		return nullptr;

	//char null_bytes[0x1000];
	//_zeromemory(null_bytes, 0x1000);

	//if (clear_header.get_decrypted())
	//	memory::_write_virtual_memory(process_handle, target_base, null_bytes, 0x1000);

	return target_base;
}


_pvoid_enc ldr::remote::load_library(HANDLE process_handle, DWORD process_id, _pvoid_enc src_data, _pvoid_enc reserved)
{
	return remote::load_library_ex(process_handle, src_data, TRUE, TRUE, FALSE, TRUE, DLL_PROCESS_ATTACH, reserved);

}
void ldr::remote::unload_library(HANDLE process_handle, DWORD process_id, _pvoid_enc base)
{
	execute_call(api::kernel32::VirtualFreeEx, process_handle, base.get_decrypted(), (SIZE_T)0, MEM_RELEASE);
}

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void __stdcall remote_shellcode(manual_mapping_data* pData) {
	if (!pData) {
		pData->hMod = (HINSTANCE)0x404040;
		return;
	}

	BYTE* pBase = pData->pbase;
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->LoadLibraryA;
	auto _GetProcAddress = pData->GetProcAddress;
#ifdef _WIN64
	auto _RtlAddFunctionTable = pData->RtlAddFunctionTable;
#endif
	auto _DllMain = reinterpret_cast<BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved)>(pBase + pOpt->AddressOfEntryPoint);

	BYTE* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta) {
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					if (((*pRelativeInfo) >> 0x0C) == IMAGE_REL_BASED_DIR64) {
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name) {
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else {
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	bool ExceptionSupportFailed = false;

	if (pData->SEHSupport) {
		auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (excep.Size) {
			if (!_RtlAddFunctionTable(
				reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + excep.VirtualAddress),
				excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase)) {
				ExceptionSupportFailed = true;
			}
		}
	}

	pData->hMod = reinterpret_cast<HINSTANCE>(pBase);

	_DllMain(pBase, DLL_PROCESS_ATTACH, (PVOID)0xa45);
}