#include "routines.h"
#include "../windows/global.h"


void watchdog_routines::memory_watch()
{
    SYSTEM_INFO sys_info;
    execute_call(windows::api::kernel32::GetSystemInfo, &sys_info);

    LPVOID minimum_application_address = sys_info.lpMinimumApplicationAddress;
    LPVOID max_application_address = sys_info.lpMaximumApplicationAddress;

    std::cout << minimum_application_address << "\n";
    std::cout << max_application_address << "\n";

    while (true)
    {
        LPVOID current_address = minimum_application_address;
        LPVOID max_address = max_application_address;

        while (true) {

            encryption::encrypted_block<MEMORY_BASIC_INFORMATION> mbi_enc;

            //  if (!memory::query_virtual_memory(current_address, mbi_enc).get_decrypted()) 
             //     break;
              //MEMORY_BASIC_INFORMATION mbi = mbi_enc.get_decrypted();

            MEMORY_BASIC_INFORMATION mbi;
            SIZE_T return_length = 0;

            if (!NT_SUCCESS(execute_call<NTSTATUS>(windows::api::ntdll::NtQueryVirtualMemory, GetCurrentProcess(),
                current_address,
                0,
                &mbi,
                sizeof(mbi),
                &return_length)))
            {
                break;
            }

            if ((mbi.Protect & PAGE_EXECUTE) ||
                (mbi.Protect & PAGE_EXECUTE_READ) ||
                (mbi.Protect & PAGE_EXECUTE_READWRITE) ||
                (mbi.Protect & PAGE_EXECUTE_WRITECOPY))
            {

                if (!windows::sub_functions::get_module_handle_where_address_resides((uintptr_t)current_address).get_decrypted())
                {
                    std::cout << "Address: " << current_address
                        << ", Base: " << mbi.BaseAddress
                        << ", Size: " << mbi.RegionSize
                        << ", State: " << mbi.State
                        << ", Type: " << mbi.Type
                        << ", Protect: " << mbi.Protect << "\n";
                }
            }

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