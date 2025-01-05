#include "routines.h"
#include "../windows/global.h"

void watchdog_routines::loaded_dll_watch_routine()
{
    while (true) {
        static secure_vector<encryption::encrypted_block<LDR_DATA_TABLE_ENTRY>> scanned_dlls;

        static auto is_already_cert_scanned = [](LDR_DATA_TABLE_ENTRY* entry) {

            for (auto& current : scanned_dlls)
            {
                auto ldr_dcr = current.get_decrypted();
                if (_memequal(&ldr_dcr, entry, sizeof(LDR_DATA_TABLE_ENTRY)))
                    return true;
            }

            return false;
        };
    
        auto peb = windows::sub_functions::get_process_peb();

        LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
        LIST_ENTRY* current = head->Flink;

        while (current != head) {
           
            LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

            if (!is_already_cert_scanned(entry))
            {
                if (!cert::is_digitally_signed(entry->FullDllName.Buffer).get_decrypted())
                    std::wcout << L"Unsigned Dll Present! " << entry->FullDllName.Buffer << std::endl;
                scanned_dlls.push_back(*entry);
            }


            current = current->Flink;
        }

        threading::sleep(1000);
    }
}
