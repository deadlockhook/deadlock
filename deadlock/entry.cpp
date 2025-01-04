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


bool is_owned_by_microsoft(const wchar_t* filePath) {

    HCATADMIN hCatAdmin = NULL;
    HANDLE hFile = NULL;
    BYTE hash[256];
    DWORD hashSize = sizeof(hash);
    bool isSigned = false;

    if (CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0)) {
        hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            if (CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hash, 0)) {
                HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashSize, 0, NULL);
                if (hCatInfo) {
                    isSigned = true;
                    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                }
            }
            CloseHandle(hFile);
        }
        CryptCATAdminReleaseContext(hCatAdmin, 0);
    }

    return isSigned;
}

bool is_digitally_signed(const wchar_t* filePath) {

    HCATADMIN hCatAdmin = NULL;
    HANDLE hFile = NULL;
    BYTE hash[256];
    DWORD hashSize = sizeof(hash);
    bool isSigned = false;

    if (CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0)) {
        hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            if (CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hash, 0)) {
                HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashSize, 0, NULL);
                if (hCatInfo) {
                    isSigned = true;
                    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                }
            }
            CloseHandle(hFile);
        }
        CryptCATAdminReleaseContext(hCatAdmin, 0);
    }

    if (isSigned)
        return true;

    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath;

    WINTRUST_DATA trustData = { 0 };
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_REVOCATION_CHECK_NONE;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &trustData);

    return (status == ERROR_SUCCESS);
}

void list_processes_and_check_signatures() {
 
    ULONG buffer_size = 0x10000;
    std::vector<BYTE> buffer(buffer_size);

    while (true) {

        NTSTATUS status = execute_call<NTSTATUS>(windows::api::ntdll::NtQuerySystemInformation, SystemProcessInformation, buffer.data(), buffer_size, &buffer_size);

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            buffer.resize(buffer_size);
            continue;
        }

        if (!NT_SUCCESS(status)) {

            return;
        }

        break;
    }

    PSYSTEM_PROCESS_INFORMATION process_info = (PSYSTEM_PROCESS_INFORMATION)buffer.data();
    do {
        if (process_info->ImageName.Buffer) {
            std::wcout << L"Process ID: " << process_info->UniqueProcessId
                << L", Name: " << process_info->ImageName.Buffer << std::endl;

            if (is_digitally_signed(process_info->ImageName.Buffer)) {
                std::wcout << L"  The process is digitally signed." << std::endl;
            }
            else {
                std::wcout << L"  The process is NOT digitally signed." << std::endl;
            }
        }
        process_info = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)process_info + process_info->NextEntryOffset);
    } while (process_info->NextEntryOffset != 0);
}



int _dl_windows_launch() {
    list_processes_and_check_signatures();
    return 0;
}
