#include "routines.h"
#include "../windows/global.h"

void CALLBACK apc_function(ULONG_PTR parameter) {
    std::cout << "APC executed with parameter: " << parameter << std::endl;
}

void watchdog_routines::thread_watch()
{
    while (true)
    {
        HANDLE snapshot = execute_call<HANDLE>(windows::api::kernel32::CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, 0);

        if (snapshot != INVALID_HANDLE_VALUE)
        {
            THREADENTRY32 te32;
            te32.dwSize = sizeof(THREADENTRY32);

            if (execute_call<BOOL>(windows::api::kernel32::Thread32First, snapshot, &te32)) {

                do {
                    if (te32.th32OwnerProcessID == windows::local_app_data::process_id.get_decrypted() && te32.th32ThreadID != execute_call<DWORD>(windows::api::kernel32::GetCurrentThreadId)) {
                        // Open a handle to the thread
                        HANDLE thread_handle = OpenThread(THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);
                        if (thread_handle) {
                            // Queue the APC
                            if (execute_call<BOOL>(windows::api::kernel32::QueueUserAPC, apc_function, thread_handle, (ULONG_PTR)te32.th32ThreadID)) {
                             //   std::cout << "APC queued to thread ID: " << te32.th32ThreadID << std::endl;
                            }
                            else {
                                std::cerr << "Failed to queue APC to thread ID: " << te32.th32ThreadID
                                    << " (Error: " << GetLastError() << ")\n";
                            }
                            execute_call(windows::api::kernel32::CloseHandle, thread_handle);
                        }
                        else {
                            std::cerr << "Failed to open thread ID: " << te32.th32ThreadID
                                << " (Error: " << GetLastError() << ")\n";
                        }
                    }
                } while (Thread32Next(snapshot, &te32));
            }

            execute_call(windows::api::kernel32::CloseHandle,snapshot);
        }

        threading::sleep(200);
    }
}