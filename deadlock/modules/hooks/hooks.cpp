#include "hooks.h"
#include "../../../windows/global.h"
#include "../watcher/intercept_and_watch.h"

void disable_sub_routine()
{
	//report
}

ULONG  __fastcall dbg_print_ex_hook(VOID)
{
	return 0;
}

LONG __fastcall rtl_unhandled_exception_filter2(__int64 a1) {
	return -1;
}

DWORD(__stdcall* _SleepEx)(DWORD dwMilliseconds, BOOL bAlertable);
DWORD __stdcall SleepExHooked(DWORD dwMilliseconds, BOOL bAlertable)
{
	return _SleepEx(dwMilliseconds, TRUE);
}


void hooks::initialize()
{
	_pvoid_enc rtn;

	watcher::create_hook((void*)windows::api::ntdll::DbgUserBreakPoint.get_decrypted(), disable_sub_routine, nullptr);
	watcher::create_hook((void*)windows::api::ntdll::NtDebugContinue.get_decrypted(), disable_sub_routine, nullptr);
	watcher::create_hook((void*)windows::api::ntdll::DbgPrintEx.get_decrypted(), dbg_print_ex_hook, nullptr);
	watcher::create_hook((void*)windows::api::ntdll::RtlUnhandledExceptionFilter2.get_decrypted(), rtl_unhandled_exception_filter2, nullptr);
	watcher::create_hook((void*)windows::api::kernelbase::module_info.find_import(ENCRYPT_STRING("SleepEx")).get_decrypted(), SleepExHooked, &rtn);
	_SleepEx = (decltype(&SleepExHooked))rtn.get_decrypted();
}