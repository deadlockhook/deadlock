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
 
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot (Error: " << GetLastError() << ")\n";
        return;
    }

    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32FirstW(snapshot, &process_entry)) {
        std::cerr << "Failed to retrieve the first process (Error: " << GetLastError() << ")\n";
        CloseHandle(snapshot);
        return;
    }

    do {
        std::wcout << L"Process ID: " << process_entry.th32ProcessID
            << L", Name: " << process_entry.szExeFile << std::endl;
        HANDLE process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_entry.th32ProcessID);
       
        if (process_handle) {
            auto file_path = windows::api::get_process_file_path_w(process_handle);
            std::wcout << "  File Path: " << file_path  << " SIGNED " << cert::is_digitally_signed(file_path.c_str()).get_decrypted() << std::endl;
            CloseHandle(process_handle);
        }
        else {
            std::wcerr << L"  Failed to open process (Error: " << GetLastError() << ")\n";
        }

    } while (Process32Next(snapshot, &process_entry));

    CloseHandle(snapshot);
}



int _dl_windows_launch() {
    list_processes_and_check_signatures();
    system("pause");
    return 0;
}
