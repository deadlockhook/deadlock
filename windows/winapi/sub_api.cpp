#include "wrapper.h"

__declspec(noinline) _lpcwstr_enc windows::sub_functions::get_module_name(_ulonglong_enc base) {

	PPEB peb = get_process_peb();

	for (PLIST_ENTRY pListEntry = (PLIST_ENTRY)peb->Ldr->InMemoryOrderModuleList.Flink;
		pListEntry != &peb->Ldr->InMemoryOrderModuleList; pListEntry = (PLIST_ENTRY)pListEntry->Flink) {

		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		PUNICODE_STRING DllBaseName = (PUNICODE_STRING)((_ulonglong)pEntry + (_ulonglong)FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, FullDllName) + sizeof(UNICODE_STRING));

		if (base.get_decrypted() == (_ulonglong)pEntry->DllBase)
			return DllBaseName->Buffer;
	}

	return nullptr;
}

__declspec(noinline) _lpcwstr_enc windows::sub_functions::get_module_full_path(_ulonglong_enc base) {

	PPEB peb = get_process_peb();

	for (PLIST_ENTRY pListEntry = (PLIST_ENTRY)peb->Ldr->InMemoryOrderModuleList.Flink;
		pListEntry != &peb->Ldr->InMemoryOrderModuleList; pListEntry = (PLIST_ENTRY)pListEntry->Flink) {

		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		if (base.get_decrypted() == (_ulonglong)pEntry->DllBase)
			return pEntry->FullDllName.Buffer;
	}

	return nullptr;
}

__declspec(noinline) _ulonglong_enc windows::sub_functions::get_module_handle(LPCWSTR lpModuleName) {

	PPEB peb = get_process_peb();

	if (lpModuleName == nullptr)
		return (_ulonglong)peb->Reserved3[1];

	for (PLIST_ENTRY pListEntry = (PLIST_ENTRY)peb->Ldr->InMemoryOrderModuleList.Flink;
		pListEntry != &peb->Ldr->InMemoryOrderModuleList; pListEntry = (PLIST_ENTRY)pListEntry->Flink) {

		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		PUNICODE_STRING DllBaseName = (PUNICODE_STRING)((_ulonglong)pEntry + (_ulonglong)FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, FullDllName) + sizeof(UNICODE_STRING));

		if (_wcscmp(DllBaseName->Buffer, lpModuleName, FALSE) == 0 || _wcscmp(pEntry->FullDllName.Buffer, lpModuleName, FALSE) == 0)
			return (_ulonglong)pEntry->DllBase;
	}

	return 0;
}

__forceinline _ulonglong_enc windows::sub_functions::get_module_size(_ulonglong_enc Module)
{
	IMAGE_DOS_HEADER* module_dos = (IMAGE_DOS_HEADER*)Module.get_decrypted();
	PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS64)((_ulonglong)module_dos + module_dos->e_lfanew);
	return (_ulonglong)nt_headers->OptionalHeader.SizeOfImage;
}

__declspec(noinline) _ulonglong_enc windows::sub_functions::get_proc_address(_ulonglong_enc module_handle, LPCSTR proc_name, _ulonglong_enc module_size) {

	//vm_low_start

	const auto pBaseAddress = (const uint8_t*)(module_handle.get_decrypted());
	const auto pBaseName = proc_name;

	size_t sizeExportLen = _strlen(pBaseName);

	if (sizeExportLen > 0)
	{
		const auto pIDH = (const IMAGE_DOS_HEADER*)(pBaseAddress);

		if (pIDH->e_magic == IMAGE_DOS_SIGNATURE)
		{
			const auto pINH = reinterpret_cast<const IMAGE_NT_HEADERS64*>(pBaseAddress + pIDH->e_lfanew);

			if (pINH->Signature == IMAGE_NT_SIGNATURE)
			{
				const IMAGE_OPTIONAL_HEADER64* pIOH = &pINH->OptionalHeader;
				const uintptr_t nExportDirectorySize = pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
				const uintptr_t uExportDirectoryAddress = pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

				PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)pBaseAddress +
					pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

				const auto* const rva_table =
					reinterpret_cast<const unsigned long*>((LPBYTE)pBaseAddress + ExportDirectory->AddressOfFunctions);

				const auto* const ord_table = reinterpret_cast<const unsigned short*>(
					(LPBYTE)pBaseAddress + ExportDirectory->AddressOfNameOrdinals);

				PDWORD name = (PDWORD)((LPBYTE)pBaseAddress + ExportDirectory->AddressOfNames);

				for (DWORD i = 0; i < ExportDirectory->NumberOfFunctions; i++)
				{
					const char* FunctionName = ((const char*)pBaseAddress + name[i]);

					if (_strcmp_cmplen(pBaseName, FunctionName, FALSE) == 0)
					{
						unsigned long long proc_addr = (unsigned long long)((void*)((LPBYTE)pBaseAddress + rva_table[ord_table[i]]));
						if (in_range(proc_addr, (unsigned long long)pBaseAddress, (unsigned long long)pBaseAddress + module_size.get_decrypted()))
							return proc_addr;
					}
				}
			}
		}
	}

	//vm_low_end

	return 0;
}