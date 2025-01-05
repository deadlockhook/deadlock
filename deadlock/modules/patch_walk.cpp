#include "routines.h"
#include "../windows/global.h"
#include "watcher/intercept_and_watch.h"

_bool_enc protect_module_exports_from_hooks(windows::api::Module module)
{
	//use zydis/capstone to check for inline hooks on export

	auto reassambled_module = module.reassmble_executable_file_for_reference();

	if (!reassambled_module.get_decrypted())
		return FALSE;

	//vm_low_start

	struct patch_walk_functions
	{
		unsigned long long function_address;
		unsigned long long patch;
		const char* function_name;
	};

	secure_vector<patch_walk_functions> vec_function_list;

	static auto exist_in_list = [](_ulonglong function_address, secure_vector<patch_walk_functions>& list) {

		for (auto& current : list)
		{
			if (current.function_address == function_address)
				return true;
		}

		return false;
		};

	const auto file_base_address = (const uint8_t*)(reassambled_module.get_decrypted());
	const auto module_base_address = (const uint8_t*)module.module_base.get_decrypted();

	const auto pIDH = (const IMAGE_DOS_HEADER*)(file_base_address);

	if (pIDH->e_magic == IMAGE_DOS_SIGNATURE)
	{
		const auto pINH = reinterpret_cast<const IMAGE_NT_HEADERS64*>(file_base_address + pIDH->e_lfanew);

		if (pINH->Signature == IMAGE_NT_SIGNATURE)
		{
			const IMAGE_OPTIONAL_HEADER64* pIOH = &pINH->OptionalHeader;
			const uintptr_t nExportDirectorySize = pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
			const uintptr_t uExportDirectoryAddress = pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

			PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)file_base_address +
				pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

			const auto* const rva_table =
				reinterpret_cast<const unsigned long*>((LPBYTE)file_base_address + ExportDirectory->AddressOfFunctions);

			const auto* const ord_table = reinterpret_cast<const unsigned short*>(
				(LPBYTE)file_base_address + ExportDirectory->AddressOfNameOrdinals);

			const auto* const rva_table_loaded =
				reinterpret_cast<const unsigned long*>((LPBYTE)module_base_address + ExportDirectory->AddressOfFunctions);

			const auto* const ord_table_loaded = reinterpret_cast<const unsigned short*>(
				(LPBYTE)module_base_address + ExportDirectory->AddressOfNameOrdinals);

			PDWORD name = (PDWORD)((LPBYTE)file_base_address + ExportDirectory->AddressOfNames);

			for (DWORD i = 0; i < ExportDirectory->NumberOfFunctions; i++)
			{
				const char* FunctionName = ((const char*)module.module_base.get_decrypted() + name[i]);

				unsigned long long proc_addr_on_file = (unsigned long long)((void*)((LPBYTE)file_base_address + rva_table[ord_table[i]]));
				unsigned long long proc_addr = (unsigned long long)((void*)((LPBYTE)module.module_base.get_decrypted() + rva_table_loaded[ord_table_loaded[i]]));

				if (in_range(proc_addr_on_file, (unsigned long long)file_base_address, (unsigned long long)file_base_address + module.module_size.get_decrypted()) && !exist_in_list(proc_addr, vec_function_list))
				{
					if (rva_table[ord_table[i]] != rva_table_loaded[ord_table_loaded[i]])
					{
						std::cout << "[deadlock] crashable logic [1] [protect_module_exports_from_hooks]\n";
						//dl_api::protection::reporting::report(dl_api::protection::reporting::wd_crash);
						return FALSE;
					}
					else
					{
						unsigned long long patch = *(unsigned long long*)proc_addr;
						unsigned long long patch_on_file = *(unsigned long long*)proc_addr_on_file;

						if (patch != patch_on_file)
						{
							auto section_in_file = module.get_section_where_address_resides((_ulonglong)file_base_address, proc_addr_on_file);
							auto section_in_loaded = module.get_section_where_address_resides((_ulonglong)module.module_base.get_decrypted(), proc_addr);

							if (section_in_file && !section_in_loaded)
							{
								std::cout << "[deadlock] crashable logic [2] [protect_module_exports_from_hooks]\n";
								return FALSE;
							}
							else if (section_in_file && section_in_loaded)
							{
								if (section_in_file->PointerToRawData != section_in_loaded->PointerToRawData)
								{
									std::cout << "[deadlock] crashable logic [3] [protect_module_exports_from_hooks]\n";
									return FALSE;
								}
								else
									continue;
							}
							else
								continue;
						}
						else
							vec_function_list.emplace_back(patch_walk_functions(proc_addr, patch, FunctionName));
					}
				}
			}
		}
	}

	//vm_low_end

		//vm_mutate_start

		watcher::hook_watch_lock.lock();

	for (auto& function : vec_function_list)
	{
		watcher::vec_patch_walk.emplace_back(watcher::watchdog_patch_walk{ TRUE, function.patch,
			sizeof(unsigned long long), (void*)function.function_address, (void*)function.function_address,function.function_name, module.module_name });
	}

	watcher::hook_watch_lock.release();

	memory::_free(reassambled_module);

//	vm_mutate_end

    return true;
}

void watchdog_routines::patch_walk()
{
	protect_module_exports_from_hooks(windows::api::kernel32::module_info);
	protect_module_exports_from_hooks(windows::api::kernelbase::module_info);
	protect_module_exports_from_hooks(windows::api::ntdll::module_info);
	//protect_module_exports_from_hooks(windows::api::user32::module_info);
	protect_module_exports_from_hooks(windows::api::bcrypt::module_info);

	while (true)
	{

		watcher::hook_watch_lock.lock();

		for (int current = 0; current < watcher::vec_patch_walk.size(); current++)
		{
			auto hook = watcher::vec_patch_walk[current];

			unsigned long long patch_ul = hook.patch.get_decrypted();

			if (hook.patch.get_decrypted() != *(unsigned long long*)(hook.patch_target.get_decrypted()) && hook.enabled.get_decrypted())
			{
				unsigned long long buffer_stored = hook.patch.get_decrypted();

				if (!_memequal((void*)hook.target_function.get_decrypted(), (void*)&buffer_stored, hook.patch_size.get_decrypted()))
				{
					std::cout << "patch violation detected\n";
				}
				// dl_api::protection::reporting::report(reporting::watchdog_reports::wd_patch_integrity_failure, &watcher::vec_patch_walk[current]);
			}
		}

		watcher::hook_watch_lock.release();

		std::cout << "[patch_walk] tick\n";
		threading::sleep(1000);
	}

}