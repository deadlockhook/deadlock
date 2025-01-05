#define EXE
#include "../windows/global.h"
#include <iostream>
#include <wintrust.h>
#include <softpub.h>
#include <vector>
#include <ntstatus.h>
#include <mscat.h>
#pragma comment(lib, "WinTrust.lib")


typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

void print_error(const char* message) {
    std::cerr << message << " (Error Code: " << GetLastError() << ")" << std::endl;
}

void list_processes_and_check_signatures() {

    HANDLE snapshot = execute_call<HANDLE>(windows::api::kernel32::CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);

    if (!execute_call<BOOL>(windows::api::kernel32::Process32First, snapshot, &process_entry)) {
        execute_call<BOOL>(windows::api::kernel32::CloseHandle, snapshot);
        return;
    }

    do {

        HANDLE process_handle = execute_call<HANDLE>(windows::api::kernel32::OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_entry.th32ProcessID);

        if (process_handle) {
            auto file_path = windows::api::get_process_file_path_w(process_handle);

            if (!cert::is_digitally_signed(file_path.c_str()).get_decrypted())
                std::wcout << "  File Path: " << file_path << std::endl;
            
            execute_call<BOOL>(windows::api::kernel32::CloseHandle, process_handle);
        }
        else {
            std::wcerr << L"  Failed to open process (Error: " << GetLastError() << ")\n";
        }

    } while (execute_call<BOOL>(windows::api::kernel32::Process32Next, snapshot, &process_entry));

    execute_call<BOOL>(windows::api::kernel32::CloseHandle, snapshot);
}

void exec_service() {

    list_processes_and_check_signatures();

}

int _dl_windows_launch() {
    threading::create_thread((threading::fn_thread_callback)exec_service, 0);
    execute_call(windows::api::kernel32::SuspendThread, execute_call<HANDLE>(windows::api::kernel32::GetCurrentThread));
    return 0;
}
