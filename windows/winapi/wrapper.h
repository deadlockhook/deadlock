#pragma once
#include "winapi_structs.h"
#include "../common.h"
#include "../encryption/compile_and_runtime.h"
#include "../typedefs.h"
#include "../crt/crt.h"
#include "../crt/sec_string.h"
#include "../encryption/enc_string.h"


namespace windows
{
    namespace sub_functions {
        __forceinline PPEB get_process_peb() {
            return reinterpret_cast<PPEB>(__readgsqword(0x60));
        }

        __declspec(noinline) _lpcwstr_enc get_module_name(_ulonglong_enc base);
        __declspec(noinline) _lpcwstr_enc get_module_full_path(_ulonglong_enc base);
        __declspec(noinline) _ulonglong_enc get_module_handle(LPCWSTR lpModuleName);
        __forceinline _ulonglong_enc get_module_size(_ulonglong_enc Module);
        __declspec(noinline) _ulonglong_enc get_proc_address(_ulonglong_enc module_handle, LPCSTR proc_name, _ulonglong_enc module_size);

        __declspec(noinline) _ulonglong_enc get_module_where_address_resides(_ulonglong_enc address);
    }
}

template <typename T = void, typename... Args>
__forceinline T execute_call(_ulonglong_enc& Function, Args... argList) {
    //virtualize call
    using FnCast = T(*)(Args...);
    if constexpr (std::is_same_v<T, void>) {
        ((FnCast)Function.get_decrypted())(argList...);
    }
    else
        return((FnCast)Function.get_decrypted())(argList...);
    //virtualize call
}

template <typename T = void, typename... Args>
__forceinline T execute_call(_pvoid_enc& Function, Args... argList) {
    //virtualize call
    using FnCast = T(*)(Args...);
    if constexpr (std::is_same_v<T, void>) {
        ((FnCast)Function.get_decrypted())(argList...);
    }
    else
        return((FnCast)Function.get_decrypted())(argList...);
    //virtualize call
}

namespace windows
{

    namespace local_app_data
    {
        inline _int_enc process_id;
        inline encryption::encrypted_block<HANDLE> process_handle;
        inline _ulonglong_enc jmp_address;
    }
    namespace api
    {
        inline _ulonglong_enc LoadLibraryW;

        struct Module
        {
            Module()
            {

            }
            __forceinline void initialize(const wchar_t* ModuleName);
            __forceinline _ulonglong_enc find_import(const char* ImportName);
            __forceinline _bool_enc valid();

            __declspec(noinline) PIMAGE_SECTION_HEADER get_section_where_address_resides(_ulonglong_enc module_base_addr, _ulonglong_enc address);

            __declspec(noinline) _pvoid_enc reassmble_executable_file_for_reference();

            __forceinline _ulonglong_enc find_pattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, char* szMask);


            _lpcwstr_enc module_name;
            _lpcwstr_enc module_full_path;
            _ulonglong_enc module_base;
            _ulonglong_enc module_size;
        };

        inline Module local_module;

        namespace kernel32
        {
            inline Module module_info;
            inline _ulonglong_enc CreateThread;
            inline _ulonglong_enc CloseHandle;
            inline _ulonglong_enc Sleep;
            inline _ulonglong_enc GetTickCount64;
            inline _ulonglong_enc LoadLibraryA;
            inline _ulonglong_enc GetProcAddress;

            inline _ulonglong_enc VirtualAlloc;
            inline _ulonglong_enc VirtualQuery;
            inline _ulonglong_enc VirtualFree;
            inline _ulonglong_enc VirtualAllocEx;
            inline _ulonglong_enc VirtualQueryEx;
            inline _ulonglong_enc VirtualFreeEx;
            inline _ulonglong_enc VirtualLock;
            inline _ulonglong_enc VirtualProtect;
            inline _ulonglong_enc VirtualProtectEx;

            inline _ulonglong_enc GetThreadContext;
            inline _ulonglong_enc SetThreadContext;

            inline _ulonglong_enc GetCurrentProcess;
            inline _ulonglong_enc GetCurrentProcessId;
            inline _ulonglong_enc GetCurrentThreadId;

            inline _ulonglong_enc GetLastError;

            inline _ulonglong_enc CreateToolhelp32Snapshot;
            inline _ulonglong_enc Thread32First;
            inline _ulonglong_enc Thread32Next;

            inline _ulonglong_enc SuspendThread;
            inline _ulonglong_enc ResumeThread;
            inline _ulonglong_enc OpenThread;
            inline _ulonglong_enc FlushInstructionCache;
            inline _ulonglong_enc GetSystemInfo;

            inline _ulonglong_enc CreateFileW;
            inline _ulonglong_enc ReadFile;
            inline _ulonglong_enc GetFileSize;
            inline _ulonglong_enc GetFileSizeEx;

            inline _ulonglong_enc CheckRemoteDebuggerPresent;
            inline _ulonglong_enc OpenProcess;

            inline _ulonglong_enc K32QueryWorkingSetEx;

            inline _ulonglong_enc MultiByteToWideChar;
            inline _ulonglong_enc WideCharToMultiByte;
            inline _ulonglong_enc TerminateThread;
            inline _ulonglong_enc TerminateProcess;
            inline _ulonglong_enc GetCurrentThread;
            inline _ulonglong_enc FatalExit;

            inline _ulonglong_enc FindFirstFileW;
            inline _ulonglong_enc FindNextFileW;
            inline _ulonglong_enc RemoveDirectoryW;
            inline _ulonglong_enc DeleteFileW;
            inline _ulonglong_enc FindClose;
            inline _ulonglong_enc  SetFilePointerEx;
            inline _ulonglong_enc  WriteFile;
            inline _ulonglong_enc FlushFileBuffers;

            inline _ulonglong_enc GetLogicalDrives;
            inline _ulonglong_enc GetDriveTypeW;
            inline _ulonglong_enc GetVolumeInformationW;

            inline _ulonglong_enc GetEnvironmentVariableA;
            inline _ulonglong_enc CreateFileA;
            inline _ulonglong_enc GetFileAttributesExA;
            inline _ulonglong_enc DeleteFileA;
            inline _ulonglong_enc GetFileAttributesA;
            inline _ulonglong_enc CreateDirectoryA;
            inline _ulonglong_enc WriteProcessMemory;
            inline _ulonglong_enc ReadProcessMemory;
            inline _ulonglong_enc CreateRemoteThread;
            inline _ulonglong_enc GetExitCodeProcess;
            inline _ulonglong_enc IsProcessorFeaturePresent;
            inline _ulonglong_enc CreateProcessW;
            inline _ulonglong_enc GlobalAlloc;
            inline _ulonglong_enc GlobalLock;
            inline _ulonglong_enc GlobalUnlock;
            inline _ulonglong_enc QueryDosDeviceA;
            inline _ulonglong_enc K32GetProcessImageFileNameA;

            inline _ulonglong_enc LocalFree;

            inline _ulonglong_enc Process32First;
            inline _ulonglong_enc Process32Next;

            inline _ulonglong_enc GetProcessTimes;
            inline _ulonglong_enc FileTimeToSystemTime;

            __forceinline _bool_enc initialize();
        }

        namespace kernelbase
        {
            inline Module module_info;
            inline _ulonglong_enc InitializeCriticalSection;

            __forceinline _bool_enc initialize();
        }
        namespace ntdll
        {
            inline Module module_info;

            inline _ulonglong_enc RtlInitializeCriticalSection;
            inline _ulonglong_enc RtlEnterCriticalSection;
            inline _ulonglong_enc RtlLeaveCriticalSection;
            inline _ulonglong_enc RtlDeleteCriticalSection;
            inline _ulonglong_enc RtlTryEnterCriticalSection;

            inline _ulonglong_enc RtlCreateHeap;
            inline _ulonglong_enc RtlDestroyHeap;
            inline _ulonglong_enc RtlAllocateHeap;
            inline _ulonglong_enc RtlReAllocateHeap;
            inline _ulonglong_enc RtlFreeHeap;

            inline _ulonglong_enc DbgUserBreakPoint;
            inline _ulonglong_enc NtDebugContinue;
            inline _ulonglong_enc DbgPrintEx;
            inline _ulonglong_enc RtlUnhandledExceptionFilter2;
            inline _ulonglong_enc KiUserExceptionDispatcher;

            inline _ulonglong_enc NtQueryInformationProcess;
            inline _ulonglong_enc NtSetInformationDebugObject;
            inline _ulonglong_enc NtRemoveProcessDebug;
            inline _ulonglong_enc NtQuerySystemInformation;
            inline _ulonglong_enc NtQueryObject;
            inline _ulonglong_enc CsrGetProcessId;

            inline _ulonglong_enc RtlQueryProcessDebugInformation;
            inline _ulonglong_enc RtlDestroyQueryDebugBuffer;

            inline _ulonglong_enc  RtlQueryProcessHeapInformation;
            inline _ulonglong_enc  RtlCreateQueryDebugBuffer;
            inline _ulonglong_enc NtCreateDebugObject;

            inline _ulonglong_enc ZwAllocateVirtualMemory;
            inline _ulonglong_enc ZwFreeVirtualMemory;
            inline _ulonglong_enc ZwProtectVirtualMemory;

            inline _ulonglong_enc RtlAdjustPrivilege;
            inline _ulonglong_enc NtCreateThreadEx;


            __forceinline _bool_enc initialize();
        }

        namespace bcrypt
        {
            inline Module module_info;
            inline _ulonglong_enc BCryptGenRandom;

            __forceinline _bool_enc initialize();
        }

        namespace user32
        {
            inline Module module_info;

            inline _ulonglong_enc ShowWindow;
            inline _ulonglong_enc UpdateWindow;
            inline _ulonglong_enc PeekMessageW;
            inline _ulonglong_enc TranslateMessage;
            inline _ulonglong_enc DispatchMessageW;
            inline _ulonglong_enc DestroyWindow;
            inline _ulonglong_enc UnregisterClassW;
            inline _ulonglong_enc CreateWindowExW;
            inline _ulonglong_enc RegisterClassExW;
            inline _ulonglong_enc SetThreadDpiAwarenessContext;
            inline _ulonglong_enc SetProcessDPIAware;
            inline _ulonglong_enc GetDpiForSystem;
            inline _ulonglong_enc GetDpiForWindow;
            inline _ulonglong_enc GetCursorPos;
            inline _ulonglong_enc TrackMouseEvent;
            inline _ulonglong_enc SetLayeredWindowAttributes;
            inline _ulonglong_enc GetWindowRect;
            inline _ulonglong_enc EnableWindow;
            inline _ulonglong_enc GetWindowLongW;
            inline _ulonglong_enc SetWindowLongW;
            inline _ulonglong_enc GetAsyncKeyState;
            inline _ulonglong_enc SetWindowPos;
            inline _ulonglong_enc wvsprintfA;
            inline _ulonglong_enc FindWindowA;
            inline _ulonglong_enc GetWindowThreadProcessId;
            inline _ulonglong_enc ScreenToClient;
            inline _ulonglong_enc IsWindowEnabled;
            inline _ulonglong_enc DefWindowProcW;
            inline _ulonglong_enc SetWindowLongPtrW;
            inline _ulonglong_enc PostQuitMessage;
            inline _ulonglong_enc GetForegroundWindow;
            inline _ulonglong_enc GetSystemMetrics;
            inline _ulonglong_enc OpenClipboard;
            inline _ulonglong_enc EmptyClipboard;
            inline _ulonglong_enc CloseClipboard;
            inline _ulonglong_enc SetClipboardData;
            inline _ulonglong_enc GetClipboardData;
            inline _ulonglong_enc GetWindowLongPtrW;

            __forceinline _bool_enc initialize();
        }

        namespace shcore
        {
            inline Module module_info;

            inline _ulonglong_enc SetProcessDpiAwareness;

            __forceinline _bool_enc initialize();
        }

        namespace winmm
        {
            inline Module module_info;

            inline _ulonglong_enc timeGetDevCaps;
            inline _ulonglong_enc timeBeginPeriod;

            __forceinline _bool_enc initialize();
        }

        namespace dwmapi
        {
            inline Module module_info;

            inline _ulonglong_enc DwmExtendFrameIntoClientArea;

            __forceinline _bool_enc initialize();
        }

        namespace d3d11
        {
            inline Module module_info;

            inline _ulonglong_enc D3D11CreateDeviceAndSwapChain;

            __forceinline _bool_enc initialize();
        }

        namespace Advapi32
        {
            inline Module module_info;
            inline _ulonglong_enc RegGetValueA;
            inline _ulonglong_enc RegOpenKeyExA;
            inline _ulonglong_enc RegCreateKeyExA;
            inline _ulonglong_enc RegCloseKey;
            inline _ulonglong_enc RegDeleteTreeA;

            inline _ulonglong_enc RegQueryValueExA;
            inline _ulonglong_enc RegSetValueExA;

            inline _ulonglong_enc OpenSCManagerW;
            inline _ulonglong_enc OpenServiceW;
            inline _ulonglong_enc QueryServiceStatus;
            inline _ulonglong_enc CloseServiceHandle;
            inline _ulonglong_enc ChangeServiceConfigW;
            inline _ulonglong_enc ControlService;
            inline _ulonglong_enc  OpenEventLogW;
            inline _ulonglong_enc ClearEventLogW;
            inline _ulonglong_enc CloseEventLog;

            __forceinline _bool_enc initialize();
        }

        namespace Shell32
        {
            inline Module module_info;
            inline _ulonglong_enc SHGetKnownFolderPath;
            inline _ulonglong_enc ShellExecuteW;
            inline _ulonglong_enc SHGetFolderPathA;

            __forceinline _bool_enc initialize();
        }

        namespace Dbghelp
        {
            inline Module module_info;
            inline _ulonglong_enc SymInitialize;
            inline _ulonglong_enc SymSetOptions;
            inline _ulonglong_enc SymLoadModuleEx;
            inline _ulonglong_enc SymCleanup;
            inline _ulonglong_enc SymFromName;
            inline _ulonglong_enc SymUnloadModule64;
            inline _ulonglong_enc SymGetTypeFromName;
            inline _ulonglong_enc SymGetTypeInfo;

            __forceinline _bool_enc initialize();
        }
        namespace Urlmon
        {
            inline Module module_info;
            inline _ulonglong_enc URLDownloadToFileA;

            __forceinline _bool_enc initialize();
        }

        namespace WinTrust
        {
            inline Module module_info;
            inline _ulonglong_enc CryptCATAdminAcquireContext;
            inline _ulonglong_enc CryptCATAdminCalcHashFromFileHandle;
            inline _ulonglong_enc CryptCATAdminEnumCatalogFromHash;
            inline _ulonglong_enc CryptCATAdminReleaseCatalogContext;
            inline _ulonglong_enc CryptCATAdminReleaseContext;
            inline _ulonglong_enc WinVerifyTrust;

            __forceinline _bool_enc initialize();
        }



        secure_wide_string multibyte_to_unicode(_lpcstr_enc MultibyteString);
        secure_string unicode_to_multibyte(_lpcwstr_enc WideString);

        __declspec(noinline) void reg_set_string_value(HKEY hRegistryKey, secure_string valueName, encryption::encrypted_string& data);
        __declspec(noinline) void reg_get_string_value(HKEY hRegistryKey, secure_string valueName, encryption::encrypted_string& valueOut);

        __declspec(noinline) _bool_enc is_service_running(secure_wide_string szServiceName);
        __declspec(noinline) _bool_enc disable_service(secure_wide_string szServiceName);

        __declspec(noinline) _bool_enc clear_directory(secure_wide_string szDirectoryPath);
        _bool_enc securely_delete_file(const std::wstring& file_path, int overwrite_passes = 3);
       // secure_wide_string get_known_folder_path(REFKNOWNFOLDERID folder_id);

        _bool_enc clear_registry_tree(HKEY root, const std::string& subkey);

        secure_string get_environment_variable(const char* name);

        void string_format(const _char* fmtstr, _char* BufferIn, ...);
        void string_from_guid2(const GUID& guid, char* Buffer);

        secure_string get_file_path_in_system32(const char* file_name);

        _pvoid_enc query_system_information(SYSTEM_INFORMATION_CLASS info_class);

        secure_string device_path_to_drive_path(const secure_string& device_path);
        secure_string get_process_file_path(HANDLE process_handle);
        secure_wide_string get_process_file_path_w(HANDLE process_handle);
        SYSTEMTIME get_process_creation_time(HANDLE process_handle);
    }

    __declspec(noinline) _bool_enc initialize();
}