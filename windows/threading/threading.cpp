#include "threading.h"
#include "../winapi/wrapper.h"

threading::thread_creation_info threading::create_thread(encryption::encrypted_block<fn_thread_callback> routine, _pvoid_enc arg)
{
	thread_creation_info info;
	info.routine = routine;
	info.argument = arg;
	info.handle = execute_call<HANDLE>(windows::api::kernel32::CreateThread, (LPSECURITY_ATTRIBUTES)0, (SIZE_T)0, (LPTHREAD_START_ROUTINE)routine.get_decrypted(), arg.get_decrypted(), 0, &info.thread_id);
	return info;
}


void  threading::sleep(uint32_t time)
{
	execute_call(windows::api::kernel32::Sleep, time);
}