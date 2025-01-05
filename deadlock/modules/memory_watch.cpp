#include "routines.h"
#include "../windows/global.h"

void watchdog_routines::memory_watch()
{
    SYSTEM_INFO sys_info;
    execute_call(windows::api::kernel32::GetSystemInfo, &sys_info);

    LPVOID minimum_application_address = sys_info.lpMinimumApplicationAddress;
    LPVOID max_application_address = sys_info.lpMaximumApplicationAddress;

	while (true)
	{
        LPVOID current_address = minimum_application_address;
        LPVOID max_address = max_application_address;

        while (current_address < max_address) {
 
            encryption::encrypted_block<MEMORY_BASIC_INFORMATION> mbi_enc;
  
            if (!memory::query_virtual_memory(current_address, mbi_enc).get_decrypted()) {
                std::cerr << "Failed to query memory at address " << current_address << " (Error: " << GetLastError() << ")\n";
                
                break;
            }
            MEMORY_BASIC_INFORMATION   mbi = mbi_enc.get_decrypted();
            // Print memory region details
           /*
            std::cout << "Address: " << current_address
                << ", Base: " << mbi.BaseAddress
                << ", Size: " << mbi.RegionSize
                << ", State: " << mbi.State
                << ", Type: " << mbi.Type
                << ", Protect: " << mbi.Protect << "\n";
                */
            // Move to the next memory region
            current_address = (LPBYTE)current_address + mbi.RegionSize;
        }

		std::cout << "[memory_watch] tick\n";
		threading::sleep(1000);
	}

}