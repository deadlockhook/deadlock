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


void hooks::initialize()
{
	watcher::create_hook((void*)windows::api::ntdll::DbgUserBreakPoint.get_decrypted(), disable_sub_routine, nullptr);
	watcher::create_hook((void*)windows::api::ntdll::NtDebugContinue.get_decrypted(), disable_sub_routine, nullptr);
	watcher::create_hook((void*)windows::api::ntdll::DbgPrintEx.get_decrypted(), dbg_print_ex_hook, nullptr);
	watcher::create_hook((void*)windows::api::ntdll::RtlUnhandledExceptionFilter2.get_decrypted(), rtl_unhandled_exception_filter2, nullptr);
}