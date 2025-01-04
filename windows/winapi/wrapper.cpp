#include "wrapper.h"
#include "../memory/memory.h"
#include <filesystem/filesystem.h>

__forceinline void windows::api::Module::initialize(const wchar_t* ModuleName)
{
    module_base = sub_functions::get_module_handle(ModuleName);

    unsigned long long _module_base = module_base.get_decrypted();

    if (_module_base == 0 && api::LoadLibraryW.get_decrypted() && ModuleName != nullptr)
        _module_base = reinterpret_cast<_ulonglong>(execute_call<HMODULE>(api::LoadLibraryW, ModuleName));

    if (_module_base) {
        IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)_module_base;
        IMAGE_NT_HEADERS64* nt_headers = (IMAGE_NT_HEADERS64*)(_module_base + dos_header->e_lfanew);
        module_size = nt_headers->OptionalHeader.SizeOfImage;
        module_base = _module_base;
        module_name = sub_functions::get_module_name(module_base);
        module_full_path = sub_functions::get_module_full_path(module_base);

    }
}

__declspec(noinline) _pvoid_enc windows::api::Module::reassmble_executable_file_for_reference() {

   // vm_low_start

    auto file_data = filesystem::read_file(module_full_path.get_decrypted());

    if (!file_data.get_decrypted())
        return nullptr;

    BYTE* _file_data = (BYTE*)file_data.get_decrypted();

    _pvoid_enc ret = nullptr;

    if (reinterpret_cast<IMAGE_DOS_HEADER*>(_file_data)->e_magic == 0x5A4D) {
        IMAGE_NT_HEADERS* nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(_file_data + reinterpret_cast<IMAGE_DOS_HEADER*>(_file_data)->e_lfanew);
        IMAGE_OPTIONAL_HEADER* optional_header = &nt_header->OptionalHeader;
        IMAGE_FILE_HEADER* file_header = &nt_header->FileHeader;

        if (file_header->Machine == IMAGE_FILE_MACHINE_AMD64) {

            BYTE* new_base = (BYTE*)memory::_malloc(optional_header->SizeOfImage).get_decrypted();

            if (new_base) {

                _memcpy(new_base, _file_data, 0x1000);

                IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(nt_header);

                for (UINT i = 0; i != file_header->NumberOfSections; ++i, ++section_header)
                    if (section_header->SizeOfRawData)
                        _memcpy(new_base + section_header->VirtualAddress, _file_data + section_header->PointerToRawData, section_header->SizeOfRawData);


#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

                BYTE* LocationDelta = (BYTE*)module_base.get_decrypted() - optional_header->ImageBase;

                if (LocationDelta) {
                    if (optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
                        auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(new_base + optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
                        const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
                        while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
                            UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                            WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

                            for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
                                if (*pRelativeInfo >> 0x0C == IMAGE_REL_BASED_DIR64) {
                                    UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(new_base + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
                                    *pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
                                }
                            }
                            pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
                        }
                    }
                }

                ret = new_base;
            }
        }
    }

    memory::_free(file_data);

  //  vm_low_end

    return ret;
}

__forceinline BOOLEAN _bDataCompareEx(const BYTE* pData, BYTE* bMask, const char* szMask) {
    for (; *szMask; ++szMask, ++pData, ++bMask)
        if (*szMask == 'x' && *pData != *bMask)
            return 0;
    return (*szMask) == 0;
}
__forceinline _ulonglong_enc windows::api::Module::find_pattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, char* szMask)
{
    size_t max_len = dwLen - strlen(szMask);
    for (uintptr_t i = 0; i < max_len; i++)
        if (_bDataCompareEx((BYTE*)(dwAddress + i), bMask, szMask))
            return (uintptr_t)(dwAddress + i);
    return 0;
}

__forceinline _ulonglong_enc windows::api::Module::find_import(const char* ImportName)
{
    return sub_functions::get_proc_address(module_base, ImportName, module_size);
}

PIMAGE_SECTION_HEADER windows::api::Module::get_section_where_address_resides(_ulonglong_enc base_addr, _ulonglong_enc address) {

   // vm_low_start

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)base_addr.get_decrypted();
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)dosHeader + dosHeader->e_lfanew);
    unsigned long long dcr_address = address.get_decrypted();

    IMAGE_FILE_HEADER* fileHeader = &ntHeaders->FileHeader;

    IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    for (unsigned int i = 0; i != fileHeader->NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData)
        {
            unsigned long long loaded_header_base = (unsigned long long)((unsigned char*)base_addr.get_decrypted() + sectionHeader->PointerToRawData);
            unsigned long long loaded_header_base_end = (unsigned long long)((unsigned char*)base_addr.get_decrypted() + sectionHeader->PointerToRawData + sectionHeader->SizeOfRawData);

            if (dcr_address >= loaded_header_base && dcr_address <= loaded_header_base_end)
                return pSectionHeader;
        }
    }

  //  vm_low_end

        return nullptr;
}
__forceinline _bool_enc windows::api::Module::valid()
{
    return module_base.get_decrypted() > 0 && module_size.get_decrypted() > 0;
}

__forceinline _bool_enc windows::api::kernel32::initialize()
{
    module_info.initialize(ENCRYPT_STRING(L"Kernel32.dll"));

    if (!module_info.valid().get_decrypted())
        return false;

    api::LoadLibraryW = module_info.find_import(ENCRYPT_STRING("LoadLibraryW"));
    LoadLibraryA = module_info.find_import(ENCRYPT_STRING("LoadLibraryA"));
    GetProcAddress = module_info.find_import(ENCRYPT_STRING("GetProcAddress"));
    CreateThread = module_info.find_import(ENCRYPT_STRING("CreateThread"));
    CloseHandle = module_info.find_import(ENCRYPT_STRING("CloseHandle"));
    Sleep = module_info.find_import(ENCRYPT_STRING("Sleep"));
    GetTickCount64 = module_info.find_import(ENCRYPT_STRING("GetTickCount64"));

    VirtualAlloc = module_info.find_import(ENCRYPT_STRING("VirtualAlloc"));
    VirtualQuery = module_info.find_import(ENCRYPT_STRING("VirtualQuery"));
    VirtualFree = module_info.find_import(ENCRYPT_STRING("VirtualFree"));
    VirtualAllocEx = module_info.find_import(ENCRYPT_STRING("VirtualAllocEx"));
    VirtualQueryEx = module_info.find_import(ENCRYPT_STRING("VirtualQueryEx"));
    VirtualFreeEx = module_info.find_import(ENCRYPT_STRING("VirtualFreeEx"));
    VirtualLock = module_info.find_import(ENCRYPT_STRING("VirtualLock"));
    VirtualProtect = module_info.find_import(ENCRYPT_STRING("VirtualProtect"));
    VirtualProtectEx = module_info.find_import(ENCRYPT_STRING("VirtualProtectEx"));

    GetThreadContext = module_info.find_import(ENCRYPT_STRING("GetThreadContext"));
    SetThreadContext = module_info.find_import(ENCRYPT_STRING("SetThreadContext"));

    GetCurrentProcess = module_info.find_import(ENCRYPT_STRING("GetCurrentProcess"));
    GetCurrentProcessId = module_info.find_import(ENCRYPT_STRING("GetCurrentProcessId"));

    GetLastError = module_info.find_import(ENCRYPT_STRING("GetLastError"));
    Thread32First = module_info.find_import(ENCRYPT_STRING("Thread32First"));
    Thread32Next = module_info.find_import(ENCRYPT_STRING("Thread32Next"));
    CreateToolhelp32Snapshot = module_info.find_import(ENCRYPT_STRING("CreateToolhelp32Snapshot"));
    GetCurrentThreadId = module_info.find_import(ENCRYPT_STRING("GetCurrentThreadId"));

    SuspendThread = module_info.find_import(ENCRYPT_STRING("SuspendThread"));
    ResumeThread = module_info.find_import(ENCRYPT_STRING("ResumeThread"));
    OpenThread = module_info.find_import(ENCRYPT_STRING("OpenThread"));
    FlushInstructionCache = module_info.find_import(ENCRYPT_STRING("FlushInstructionCache"));
    GetSystemInfo = module_info.find_import(ENCRYPT_STRING("GetSystemInfo"));

    CreateFileW = module_info.find_import(ENCRYPT_STRING("CreateFileW"));
    CreateFileA = module_info.find_import(ENCRYPT_STRING("CreateFileA"));
    ReadFile = module_info.find_import(ENCRYPT_STRING("ReadFile"));
    GetFileSize = module_info.find_import(ENCRYPT_STRING("GetFileSize"));
    GetFileSizeEx = module_info.find_import(ENCRYPT_STRING("GetFileSizeEx"));

    CheckRemoteDebuggerPresent = module_info.find_import(ENCRYPT_STRING("CheckRemoteDebuggerPresent"));
    OpenProcess = module_info.find_import(ENCRYPT_STRING("OpenProcess"));

    K32QueryWorkingSetEx = module_info.find_import(ENCRYPT_STRING("K32QueryWorkingSetEx"));

    MultiByteToWideChar = module_info.find_import(ENCRYPT_STRING("MultiByteToWideChar"));
    WideCharToMultiByte = module_info.find_import(ENCRYPT_STRING("WideCharToMultiByte"));
    TerminateThread = module_info.find_import(ENCRYPT_STRING("TerminateThread"));
    GetCurrentThread = module_info.find_import(ENCRYPT_STRING("GetCurrentThread"));
    TerminateProcess = module_info.find_import(ENCRYPT_STRING("TerminateProcess"));
    FatalExit = module_info.find_import(ENCRYPT_STRING("FatalExit"));

    FindFirstFileW = module_info.find_import(ENCRYPT_STRING("FindFirstFileW"));
    FindNextFileW = module_info.find_import(ENCRYPT_STRING("FindNextFileW"));
    RemoveDirectoryW = module_info.find_import(ENCRYPT_STRING("RemoveDirectoryW"));
    DeleteFileW = module_info.find_import(ENCRYPT_STRING("DeleteFileW"));
    FindClose = module_info.find_import(ENCRYPT_STRING("FindClose"));

    SetFilePointerEx = module_info.find_import(ENCRYPT_STRING("SetFilePointerEx"));
    WriteFile = module_info.find_import(ENCRYPT_STRING("WriteFile"));
    FlushFileBuffers = module_info.find_import(ENCRYPT_STRING("FlushFileBuffers"));

    GetLogicalDrives = module_info.find_import(ENCRYPT_STRING("GetLogicalDrives"));
    GetDriveTypeW = module_info.find_import(ENCRYPT_STRING("GetDriveTypeW"));
    GetVolumeInformationW = module_info.find_import(ENCRYPT_STRING("GetVolumeInformationW"));
    GetEnvironmentVariableA = module_info.find_import(ENCRYPT_STRING("GetEnvironmentVariableA"));
    GetFileAttributesExA = module_info.find_import(ENCRYPT_STRING("GetFileAttributesExA"));
    DeleteFileA = module_info.find_import(ENCRYPT_STRING("DeleteFileA"));
    GetFileAttributesA = module_info.find_import(ENCRYPT_STRING("GetFileAttributesA"));
    CreateDirectoryA = module_info.find_import(ENCRYPT_STRING("CreateDirectoryA"));

    WriteProcessMemory = module_info.find_import(ENCRYPT_STRING("WriteProcessMemory"));
    ReadProcessMemory = module_info.find_import(ENCRYPT_STRING("ReadProcessMemory"));
    CreateRemoteThread = module_info.find_import(ENCRYPT_STRING("CreateRemoteThread"));
    GetExitCodeProcess = module_info.find_import(ENCRYPT_STRING("GetExitCodeProcess"));
    IsProcessorFeaturePresent = module_info.find_import(ENCRYPT_STRING("IsProcessorFeaturePresent"));
    CreateProcessW = module_info.find_import(ENCRYPT_STRING("CreateProcessW"));
    GlobalAlloc = module_info.find_import(ENCRYPT_STRING("GlobalAlloc"));
    GlobalLock = module_info.find_import(ENCRYPT_STRING("GlobalLock"));
    GlobalUnlock = module_info.find_import(ENCRYPT_STRING("GlobalUnlock"));

    LocalFree = module_info.find_import(ENCRYPT_STRING("LocalFree"));

    return true;
}

__forceinline _bool_enc windows::api::kernelbase::initialize()
{
    module_info.initialize(ENCRYPT_STRING(L"KERNELBASE.dll"));

    if (!module_info.valid().get_decrypted())
        return false;

    return true;
}

__forceinline _bool_enc windows::api::ntdll::initialize()
{
    module_info.initialize(ENCRYPT_STRING(L"ntdll.dll"));

    if (!module_info.valid().get_decrypted())
        return false;

    local_app_data::jmp_address = module_info.find_pattern(module_info.module_base.get_decrypted() + 0x1000, module_info.module_size.get_decrypted(), (BYTE*)(PCHAR)ENCRYPT_STRING("\xFF\xE0"), (PCHAR)ENCRYPT_STRING("xx"));

    RtlInitializeCriticalSection = module_info.find_import(ENCRYPT_STRING("RtlInitializeCriticalSection"));
    RtlEnterCriticalSection = module_info.find_import(ENCRYPT_STRING("RtlEnterCriticalSection"));
    RtlLeaveCriticalSection = module_info.find_import(ENCRYPT_STRING("RtlLeaveCriticalSection"));
    RtlDeleteCriticalSection = module_info.find_import(ENCRYPT_STRING("RtlDeleteCriticalSection"));
    RtlTryEnterCriticalSection = module_info.find_import(ENCRYPT_STRING("RtlTryEnterCriticalSection"));

    RtlCreateHeap = module_info.find_import(ENCRYPT_STRING("RtlCreateHeap"));
    RtlDestroyHeap = module_info.find_import(ENCRYPT_STRING("RtlDestroyHeap"));
    RtlAllocateHeap = module_info.find_import(ENCRYPT_STRING("RtlAllocateHeap"));
    RtlReAllocateHeap = module_info.find_import(ENCRYPT_STRING("RtlReAllocateHeap"));
    RtlFreeHeap = module_info.find_import(ENCRYPT_STRING("RtlFreeHeap"));

    DbgUserBreakPoint = module_info.find_import(ENCRYPT_STRING("DbgUserBreakPoint"));
    NtDebugContinue = module_info.find_import(ENCRYPT_STRING("NtDebugContinue"));
    DbgPrintEx = module_info.find_import(ENCRYPT_STRING("DbgPrintEx"));
    RtlUnhandledExceptionFilter2 = module_info.find_import(ENCRYPT_STRING("RtlUnhandledExceptionFilter2"));
    KiUserExceptionDispatcher = module_info.find_import(ENCRYPT_STRING("KiUserExceptionDispatcher"));

    NtQueryInformationProcess = module_info.find_import(ENCRYPT_STRING("NtQueryInformationProcess"));
    NtSetInformationDebugObject = module_info.find_import(ENCRYPT_STRING("NtSetInformationDebugObject"));
    NtRemoveProcessDebug = module_info.find_import(ENCRYPT_STRING("NtRemoveProcessDebug"));
    NtQuerySystemInformation = module_info.find_import(ENCRYPT_STRING("NtQuerySystemInformation"));
    NtQueryObject = module_info.find_import(ENCRYPT_STRING("NtQueryObject"));
    CsrGetProcessId = module_info.find_import(ENCRYPT_STRING("CsrGetProcessId"));

    RtlQueryProcessDebugInformation = module_info.find_import(ENCRYPT_STRING("RtlQueryProcessDebugInformation"));
    RtlDestroyQueryDebugBuffer = module_info.find_import(ENCRYPT_STRING("RtlDestroyQueryDebugBuffer"));
    RtlQueryProcessHeapInformation = module_info.find_import(ENCRYPT_STRING("RtlQueryProcessHeapInformation"));
    RtlCreateQueryDebugBuffer = module_info.find_import(ENCRYPT_STRING("RtlCreateQueryDebugBuffer"));
    NtCreateDebugObject = module_info.find_import(ENCRYPT_STRING("NtCreateDebugObject"));

    ZwAllocateVirtualMemory = module_info.find_import(ENCRYPT_STRING("ZwAllocateVirtualMemory"));
    ZwFreeVirtualMemory = module_info.find_import(ENCRYPT_STRING("ZwFreeVirtualMemory"));
    ZwProtectVirtualMemory = module_info.find_import(ENCRYPT_STRING("ZwProtectVirtualMemory"));
    RtlAdjustPrivilege = module_info.find_import(ENCRYPT_STRING("RtlAdjustPrivilege"));
    NtCreateThreadEx = module_info.find_import(ENCRYPT_STRING("NtCreateThreadEx"));

    return true;
}

__forceinline _bool_enc windows::api::bcrypt::initialize()
{
    module_info.initialize(ENCRYPT_STRING(L"bcrypt.dll"));

    if (!module_info.valid().get_decrypted())
    {
        return false;
    }

    BCryptGenRandom = module_info.find_import(ENCRYPT_STRING("BCryptGenRandom"));

    return true;
}

__forceinline _bool_enc  windows::api::user32::initialize()
{
    module_info.initialize(ENCRYPT_STRING(L"user32.dll"));

    if (!module_info.valid().get_decrypted())
    {
        return false;
    }

    ShowWindow = module_info.find_import(ENCRYPT_STRING("ShowWindow"));
    UpdateWindow = module_info.find_import(ENCRYPT_STRING("UpdateWindow"));
    PeekMessageW = module_info.find_import(ENCRYPT_STRING("PeekMessageW"));
    TranslateMessage = module_info.find_import(ENCRYPT_STRING("TranslateMessage"));
    DispatchMessageW = module_info.find_import(ENCRYPT_STRING("DispatchMessageW"));
    DestroyWindow = module_info.find_import(ENCRYPT_STRING("DestroyWindow"));
    UnregisterClassW = module_info.find_import(ENCRYPT_STRING("UnregisterClassW"));
    CreateWindowExW = module_info.find_import(ENCRYPT_STRING("CreateWindowExW"));
    RegisterClassExW = module_info.find_import(ENCRYPT_STRING("RegisterClassExW"));;
    SetProcessDPIAware = module_info.find_import(ENCRYPT_STRING("SetProcessDPIAware"));;
    SetThreadDpiAwarenessContext = module_info.find_import(ENCRYPT_STRING("SetThreadDpiAwarenessContext"));;
    GetDpiForSystem = module_info.find_import(ENCRYPT_STRING("GetDpiForSystem"));;
    GetDpiForWindow = module_info.find_import(ENCRYPT_STRING("GetDpiForWindow"));;
    GetCursorPos = module_info.find_import(ENCRYPT_STRING("GetCursorPos"));;
    TrackMouseEvent = module_info.find_import(ENCRYPT_STRING("TrackMouseEvent"));;
    SetLayeredWindowAttributes = module_info.find_import(ENCRYPT_STRING("SetLayeredWindowAttributes"));;
    GetWindowRect = module_info.find_import(ENCRYPT_STRING("GetWindowRect"));;
    EnableWindow = module_info.find_import(ENCRYPT_STRING("EnableWindow"));;
    GetWindowLongW = module_info.find_import(ENCRYPT_STRING("GetWindowLongW"));;
    SetWindowLongW = module_info.find_import(ENCRYPT_STRING("SetWindowLongW"));;
    GetAsyncKeyState = module_info.find_import(ENCRYPT_STRING("GetAsyncKeyState"));;
    SetWindowPos = module_info.find_import(ENCRYPT_STRING("SetWindowPos"));;
    wvsprintfA = module_info.find_import(ENCRYPT_STRING("wvsprintfA"));;
    FindWindowA = module_info.find_import(ENCRYPT_STRING("FindWindowA"));;
    GetWindowThreadProcessId = module_info.find_import(ENCRYPT_STRING("GetWindowThreadProcessId"));;
    ScreenToClient = module_info.find_import(ENCRYPT_STRING("ScreenToClient"));;
    IsWindowEnabled = module_info.find_import(ENCRYPT_STRING("IsWindowEnabled"));;
    DefWindowProcW = module_info.find_import(ENCRYPT_STRING("DefWindowProcW"));;
    SetWindowLongPtrW = module_info.find_import(ENCRYPT_STRING("SetWindowLongPtrW"));;
    PostQuitMessage = module_info.find_import(ENCRYPT_STRING("PostQuitMessage"));;
    GetForegroundWindow = module_info.find_import(ENCRYPT_STRING("GetForegroundWindow"));;
    GetSystemMetrics = module_info.find_import(ENCRYPT_STRING("GetSystemMetrics"));;
    OpenClipboard = module_info.find_import(ENCRYPT_STRING("OpenClipboard"));;
    EmptyClipboard = module_info.find_import(ENCRYPT_STRING("EmptyClipboard"));;
    CloseClipboard = module_info.find_import(ENCRYPT_STRING("CloseClipboard"));;
    SetClipboardData = module_info.find_import(ENCRYPT_STRING("SetClipboardData"));;
    GetClipboardData = module_info.find_import(ENCRYPT_STRING("GetClipboardData"));;
    GetWindowLongPtrW = module_info.find_import(ENCRYPT_STRING("GetWindowLongPtrW"));;
    return true;
}

__forceinline _bool_enc windows::api::shcore::initialize()
{
    module_info.initialize(ENCRYPT_STRING(L"shcore.dll"));

    if (!module_info.valid().get_decrypted())
    {
        return false;
    }

    SetProcessDpiAwareness = module_info.find_import(ENCRYPT_STRING("SetProcessDpiAwareness"));

    return true;
}

__forceinline _bool_enc windows::api::winmm::initialize()
{
    module_info.initialize(ENCRYPT_STRING(L"Winmm.dll"));

    if (!module_info.valid().get_decrypted())
    {
        return false;
    }

    timeGetDevCaps = module_info.find_import(ENCRYPT_STRING("timeGetDevCaps"));
    timeBeginPeriod = module_info.find_import(ENCRYPT_STRING("timeBeginPeriod"));

    return true;
}

__forceinline _bool_enc windows::api::dwmapi::initialize()
{
    module_info.initialize(ENCRYPT_STRING(L"Dwmapi.dll"));

    if (!module_info.valid().get_decrypted())
        return false;

    DwmExtendFrameIntoClientArea = module_info.find_import(ENCRYPT_STRING("DwmExtendFrameIntoClientArea"));

    return true;
}

__forceinline _bool_enc windows::api::d3d11::initialize()
{
    module_info.initialize(ENCRYPT_STRING(L"D3D11.dll"));

    if (!module_info.valid().get_decrypted())
        return false;

    D3D11CreateDeviceAndSwapChain = module_info.find_import(ENCRYPT_STRING("D3D11CreateDeviceAndSwapChain"));

    return true;
}

__forceinline _bool_enc windows::api::Advapi32::initialize()
{
    module_info.initialize(ENCRYPT_STRING(L"Advapi32.dll"));

    if (!module_info.valid().get_decrypted())
        return false;

    RegGetValueA = module_info.find_import(ENCRYPT_STRING("RegGetValueA"));
    RegOpenKeyExA = module_info.find_import(ENCRYPT_STRING("RegOpenKeyExA"));
    RegCreateKeyExA = module_info.find_import(ENCRYPT_STRING("RegCreateKeyExA"));
    RegCloseKey = module_info.find_import(ENCRYPT_STRING("RegCloseKey"));
    RegQueryValueExA = module_info.find_import(ENCRYPT_STRING("RegQueryValueExA"));
    RegSetValueExA = module_info.find_import(ENCRYPT_STRING("RegSetValueExA"));
    RegDeleteTreeA = module_info.find_import(ENCRYPT_STRING("RegDeleteTreeA"));

    OpenSCManagerW = module_info.find_import(ENCRYPT_STRING("OpenSCManagerW"));
    OpenServiceW = module_info.find_import(ENCRYPT_STRING("OpenServiceW"));
    QueryServiceStatus = module_info.find_import(ENCRYPT_STRING("QueryServiceStatus"));
    CloseServiceHandle = module_info.find_import(ENCRYPT_STRING("CloseServiceHandle"));
    ChangeServiceConfigW = module_info.find_import(ENCRYPT_STRING("ChangeServiceConfigW"));
    ControlService = module_info.find_import(ENCRYPT_STRING("ControlService"));

    OpenEventLogW = module_info.find_import(ENCRYPT_STRING("OpenEventLogW"));
    ClearEventLogW = module_info.find_import(ENCRYPT_STRING("ClearEventLogW"));
    CloseEventLog = module_info.find_import(ENCRYPT_STRING("CloseEventLog"));

    return true;
}

__forceinline _bool_enc windows::api::Shell32::initialize()
{
    module_info.initialize(ENCRYPT_STRING(L"Shell32.dll"));

    if (!module_info.valid().get_decrypted())
        return false;

    SHGetKnownFolderPath = module_info.find_import(ENCRYPT_STRING("SHGetKnownFolderPath"));
    ShellExecuteW = module_info.find_import(ENCRYPT_STRING("ShellExecuteW"));
    SHGetFolderPathA = module_info.find_import(ENCRYPT_STRING("SHGetFolderPathA"));

    return true;
}


__forceinline _bool_enc windows::api::Dbghelp::initialize()
{
    module_info.initialize(ENCRYPT_STRING(L"Dbghelp.dll"));

    if (!module_info.valid().get_decrypted())
        return false;

    SymInitialize = module_info.find_import(ENCRYPT_STRING("SymInitialize"));
    SymSetOptions = module_info.find_import(ENCRYPT_STRING("SymSetOptions"));
    SymLoadModuleEx = module_info.find_import(ENCRYPT_STRING("SymLoadModuleEx"));
    SymCleanup = module_info.find_import(ENCRYPT_STRING("SymCleanup"));
    SymFromName = module_info.find_import(ENCRYPT_STRING("SymFromName"));
    SymUnloadModule64 = module_info.find_import(ENCRYPT_STRING("SymUnloadModule64"));
    SymGetTypeFromName = module_info.find_import(ENCRYPT_STRING("SymGetTypeFromName"));
    SymGetTypeInfo = module_info.find_import(ENCRYPT_STRING("SymGetTypeInfo"));
    return true;
}


__forceinline _bool_enc windows::api::Urlmon::initialize()
{
    module_info.initialize(ENCRYPT_STRING(L"Urlmon.dll"));

    if (!module_info.valid().get_decrypted())
        return false;

    URLDownloadToFileA = module_info.find_import(ENCRYPT_STRING("URLDownloadToFileA"));

    return true;
}
__declspec(noinline) _bool_enc windows::api::is_service_running(secure_wide_string szServiceName) {

    _bool_enc ret = false;

    auto sc_manager = execute_call<SC_HANDLE>(Advapi32::OpenSCManagerW, nullptr, nullptr, SC_MANAGER_CONNECT);

    if (sc_manager) {

        auto service = execute_call<SC_HANDLE>(Advapi32::OpenServiceW, sc_manager, szServiceName.c_str(), SERVICE_QUERY_STATUS);

        if (service)
        {
            SERVICE_STATUS status;

            if (execute_call<BOOL>(Advapi32::QueryServiceStatus, service, &status))
            {
                if (status.dwCurrentState != SERVICE_STOPPED) {
                    execute_call<BOOL>(Advapi32::CloseServiceHandle, service);
                    ret = TRUE;
                }
            }

            execute_call<BOOL>(Advapi32::CloseServiceHandle, service);
        }

        execute_call<BOOL>(Advapi32::CloseServiceHandle, sc_manager);
    }

    return ret;
}

__declspec(noinline) _bool_enc windows::api::disable_service(secure_wide_string szServiceName) {

    _bool_enc ret = false;

    auto sc_manager = execute_call<SC_HANDLE>(Advapi32::OpenSCManagerW, nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);

    if (sc_manager) {

        auto service = execute_call<SC_HANDLE>(Advapi32::OpenServiceW, sc_manager, szServiceName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG);

        if (service)
        {
            SERVICE_STATUS status;
            if (execute_call<BOOL>(Advapi32::QueryServiceStatus, service, &status))
            {
                if (status.dwCurrentState != SERVICE_STOPPED && status.dwCurrentState != SERVICE_STOP_PENDING)
                {
                    if (execute_call<BOOL>(Advapi32::ControlService, service, SERVICE_CONTROL_STOP, &status))
                    {
                        int tries = 20;

                        while (status.dwCurrentState != SERVICE_STOPPED && tries > 0)
                        {
                            --tries;
                            execute_call<BOOL>(kernel32::Sleep, 100);
                            execute_call<BOOL>(Advapi32::QueryServiceStatus, service, &status);
                        }
                    }
                }
            }

            if (execute_call<BOOL>(Advapi32::ChangeServiceConfigW, service, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr))
            {
                ret = TRUE;
            }

            execute_call<BOOL>(Advapi32::CloseServiceHandle, service);
        }

        execute_call<BOOL>(Advapi32::CloseServiceHandle, sc_manager);
    }

    return ret;
}

/*
secure_wide_string windows::api::get_known_folder_path(REFKNOWNFOLDERID folder_id) {
    PWSTR path = NULL;
    if (execute_call<HRESULT>(Shell32::SHGetKnownFolderPath, folder_id, 0, NULL, &path) == S_OK) {
        secure_wide_string result(path);
        CoTaskMemFree(path);
        return result;
    }
    return L"";
}
*/

_bool_enc  windows::api::securely_delete_file(const std::wstring& file_path, int overwrite_passes) {
    _bool_enc ret = false;

    HANDLE h_file = execute_call<HANDLE>(kernel32::CreateFileW, file_path.c_str(), GENERIC_WRITE, 0, (LPSECURITY_ATTRIBUTES)nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (h_file == INVALID_HANDLE_VALUE) {
        ret = execute_call<BOOL>(kernel32::DeleteFileW, file_path.c_str());
        return ret;
    }

    LARGE_INTEGER file_size;
    if (!execute_call<BOOL>(kernel32::GetFileSizeEx, h_file, &file_size)) {
        ret = execute_call<BOOL>(kernel32::DeleteFileW, file_path.c_str());
        execute_call<BOOL>(kernel32::CloseHandle, h_file);
        return ret;
    }

    std::vector<char> buffer((size_t)file_size.QuadPart, 0);

    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<unsigned short> distribution(0, 255);

    for (int pass = 0; pass < overwrite_passes; ++pass) {

        for (auto& byte : buffer)
            byte = static_cast<char>(distribution(generator));

        DWORD bytes_written = 0;
        execute_call<BOOL>(kernel32::SetFilePointerEx, h_file, LARGE_INTEGER{ 0 }, (PLARGE_INTEGER)nullptr, FILE_BEGIN);
        execute_call<BOOL>(kernel32::WriteFile, h_file, buffer.data(), static_cast<DWORD>(buffer.size()), &bytes_written, (LPOVERLAPPED)nullptr);
        execute_call<BOOL>(kernel32::FlushFileBuffers, h_file);
    }

    execute_call<BOOL>(kernel32::CloseHandle, h_file);

    ret = execute_call<BOOL>(kernel32::DeleteFileW, file_path.c_str());

    return ret;
}

__declspec(noinline) _bool_enc windows::api::clear_directory(secure_wide_string szDirectoryPath) {

    _bool_enc ret = false;

    WIN32_FIND_DATAW find_file_data;
    HANDLE h_find = INVALID_HANDLE_VALUE;

    secure_wide_string search_path = szDirectoryPath + L"\\*";

    h_find = execute_call<HANDLE>(kernel32::FindFirstFileW, search_path.c_str(), &find_file_data);

    if (h_find == INVALID_HANDLE_VALUE) {
        return false;
    }

    do {
        secure_wide_string item_name = find_file_data.cFileName;

        if (item_name == L"." || item_name == L"..") {
            continue;
        }

        secure_wide_string full_item_path = szDirectoryPath + L"\\" + item_name;

        if (find_file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            clear_directory(full_item_path);
            execute_call<BOOL>(kernel32::RemoveDirectoryW, full_item_path.c_str());
        }
        else {
            securely_delete_file(full_item_path);
        }

    } while (execute_call<BOOL>(kernel32::FindNextFileW, h_find, &find_file_data) != 0);

    execute_call<BOOL>(kernel32::FindClose, h_find);

    ret = true;
    return ret;
}


_bool_enc windows::api::clear_registry_tree(HKEY root, const std::string& subkey) {
    HKEY hKey;
    LONG result = execute_call<LONG>(
        windows::api::Advapi32::RegOpenKeyExA,
        root,
        subkey.c_str(),
        0,
        KEY_ALL_ACCESS,
        &hKey
    );

    if (result == ERROR_SUCCESS) {
        if (execute_call<LONG>(windows::api::Advapi32::RegDeleteTreeA, hKey, nullptr) == ERROR_SUCCESS) {
            execute_call<LONG>(windows::api::Advapi32::RegCloseKey, hKey);
            return true;
        }
        else {
            execute_call<LONG>(windows::api::Advapi32::RegCloseKey, hKey);
        }
    }

    return false;
}

__declspec(noinline) _bool_enc windows::initialize()
{
   // vm_low_start

        api::local_module.initialize(NULL);
    if (api::kernelbase::initialize().get_decrypted()
        && api::kernel32::initialize().get_decrypted()
        && api::ntdll::initialize().get_decrypted()
        && api::bcrypt::initialize().get_decrypted()
        && api::user32::initialize().get_decrypted()
        && api::shcore::initialize().get_decrypted()
        && api::winmm::initialize().get_decrypted()
        && api::dwmapi::initialize().get_decrypted()
        && api::d3d11::initialize().get_decrypted()
        && api::Advapi32::initialize().get_decrypted()
        && api::Shell32::initialize().get_decrypted()
        && api::Dbghelp::initialize().get_decrypted()
        && api::Urlmon::initialize().get_decrypted())
    {
        local_app_data::process_id = execute_call<DWORD>(api::kernel32::GetCurrentProcessId);
        local_app_data::process_handle = execute_call<HANDLE>(api::kernel32::GetCurrentProcess);
        return true;
    }

  //  vm_low_end

        return false;
}

void* windows::api::query_system_information(SYSTEM_INFORMATION_CLASS info_class) {

    ULONG buffer_size = 0;

    if (execute_call<NTSTATUS>(windows::api::ntdll::NtQuerySystemInformation, SystemProcessInformation, nullptr, 0, &buffer_size) == STATUS_INFO_LENGTH_MISMATCH)
    {
        void* buffer = memory::_malloc(buffer_size).get_decrypted();

        if (NT_SUCCESS(execute_call<NTSTATUS>(windows::api::ntdll::NtQuerySystemInformation, SystemProcessInformation, buffer, buffer_size, &buffer_size)))
        {
            return buffer;
        }

        memory::_free(buffer);
    }

    return nullptr;
}

secure_wide_string windows::api::multibyte_to_unicode(_lpcstr_enc MultibyteString) {

    int size_needed = execute_call<int>(kernel32::MultiByteToWideChar, (UINT)CP_UTF8, (DWORD)0, MultibyteString.get_decrypted(), (DWORD)-1, (LPWSTR)nullptr, 0);

    if (size_needed > 0) {

        secure_wide_string wstr(size_needed - 1, L'\0');

        execute_call<int>(kernel32::MultiByteToWideChar, CP_UTF8, 0, MultibyteString.get_decrypted(), -1, &wstr[0], size_needed);

        return wstr;
    }

    return  secure_wide_string();
}

secure_string windows::api::unicode_to_multibyte(_lpcwstr_enc WideString) {

    int size_needed = execute_call<int>(kernel32::WideCharToMultiByte, (UINT)CP_UTF8, (DWORD)0, (LPCWCH)WideString.get_decrypted(),
        (int)-1, (LPSTR) nullptr, (int)0, (LPCCH)nullptr, (LPBOOL)nullptr);

    if (size_needed > 0) {

        secure_string str(size_needed - 1, '\0');

        execute_call<_int>(kernel32::WideCharToMultiByte, (UINT)CP_UTF8, (DWORD)0, (LPCWCH)WideString.get_decrypted(),
            (int)-1, &str[0], (int)size_needed, (LPCCH)nullptr, (LPBOOL)nullptr);

        return str;
    }

    return  secure_string();
}

__declspec(noinline) void windows::api::reg_set_string_value(HKEY hRegistryKey, secure_string valueName, encryption::encrypted_string& data)
{
    encryption::encrypted_string DecryptedData;
    encryption::encrypt_decrypt_string(data, DecryptedData);

    secure_string DecryptedString = DecryptedData.get_string();


    ((execute_call<LSTATUS>(Advapi32::RegSetValueExA, (HKEY)hRegistryKey,
        (LPCSTR)valueName.c_str(),
        (DWORD)0,
        (DWORD)REG_SZ,
        (CONST BYTE*)(DecryptedString.c_str()),
        (DWORD)(DecryptedString.size() + 1) * sizeof(char)) == ERROR_SUCCESS));
}

__declspec(noinline) void windows::api::reg_get_string_value(HKEY hRegistryKey, secure_string valueName, encryption::encrypted_string& valueOut) {

    DWORD dwBytes = 128;
    char Buffer[128];

    if (execute_call<LSTATUS>(Advapi32::RegQueryValueExA, (HKEY)hRegistryKey, (LPCSTR)valueName.c_str(), (LPDWORD)nullptr, (LPDWORD)nullptr, (LPBYTE)Buffer, (LPDWORD)&dwBytes) == ERROR_SUCCESS)
        encrypt_decrypt_string(Buffer, valueOut);
}

void windows::api::string_format(const _char* fmtstr, _char* BufferIn, ...)
{
    DWORD dwRet;
    va_list v1;
    va_start(v1, fmtstr);
    execute_call(user32::wvsprintfA, BufferIn, fmtstr, v1);
    va_end(v1);
}


void windows::api::string_from_guid2(const GUID& guid, char* Buffer) {
    string_format((PCHAR)ENCRYPT_STRING("%08lX-%04hX-%04hX-%02X%02X-%02X%02X%02X%02X%02X%02X"), Buffer,
        guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
        guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
}

secure_string  windows::api::get_environment_variable(const char* name) {
    char path[MAX_PATH];
    execute_call<DWORD>(windows::api::kernel32::GetEnvironmentVariableA, name, path, MAX_PATH);
    return path;
}

secure_string windows::api::get_file_path_in_system32(const char* file_name)
{
    auto path = get_environment_variable((PCHAR)ENCRYPT_STRING("systemroot"));

    if (!path.size())
        return "";

    path += (PCHAR)ENCRYPT_STRING("\\System32\\");
    path += file_name;

    return path;
}