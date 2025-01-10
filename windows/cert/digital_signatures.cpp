#include "digital_signatures.h"
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#pragma comment(lib, "WinTrust.lib")
#include "../winapi/wrapper.h"

_bool_enc cert::is_present_in_cat(const wchar_t* filePath) {

    HCATADMIN cat_admin = NULL;
    HANDLE file_handle = NULL;
    BYTE hash[256];
    DWORD hash_size = sizeof(hash);
    bool is_signed = false;

    if (execute_call<BOOL>(windows::api::WinTrust::CryptCATAdminAcquireContext,&cat_admin, NULL, 0)) {
        file_handle = execute_call<HANDLE>(windows::api::kernel32::CreateFileW, filePath, GENERIC_READ, FILE_SHARE_READ,(LPSECURITY_ATTRIBUTES) NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file_handle != INVALID_HANDLE_VALUE) {
            if (execute_call<BOOL>(windows::api::WinTrust::CryptCATAdminCalcHashFromFileHandle, file_handle, &hash_size, hash, 0)) {
                HCATINFO hCatInfo = execute_call<HCATINFO>(windows::api::WinTrust::CryptCATAdminEnumCatalogFromHash, cat_admin, hash, hash_size, 0, (HCATINFO*)NULL);
                if (hCatInfo) {  
                    is_signed = true; 
                    execute_call<BOOL>(windows::api::WinTrust::CryptCATAdminReleaseCatalogContext, cat_admin, hCatInfo, 0);
                }
            }
            execute_call(windows::api::kernel32::CloseHandle, file_handle);
        }
        execute_call(windows::api::WinTrust::CryptCATAdminReleaseContext, cat_admin, 0);
    }

    return is_signed;
}

_bool_enc  cert::is_digitally_signed(const wchar_t* filePath) {

    if (is_present_in_cat(filePath).get_decrypted())
        return true;

    WINTRUST_FILE_INFO file_info = { 0 };
    file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
    file_info.pcwszFilePath = filePath;

    WINTRUST_DATA wtrust_data = { 0 };
    wtrust_data.cbStruct = sizeof(WINTRUST_DATA);
    wtrust_data.dwUIChoice = WTD_UI_NONE;
    wtrust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtrust_data.dwUnionChoice = WTD_CHOICE_FILE;
    wtrust_data.pFile = &file_info;
    wtrust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    wtrust_data.dwProvFlags = WTD_REVOCATION_CHECK_NONE;

    GUID policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    LONG status = execute_call<LONG>(windows::api::WinTrust::WinVerifyTrust, NULL, &policy_guid, &wtrust_data);

    wtrust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    execute_call(windows::api::WinTrust::WinVerifyTrust, NULL, &policy_guid, &wtrust_data);

    return (status == ERROR_SUCCESS);
}
