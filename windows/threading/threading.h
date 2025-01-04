#pragma once

#include "../common.h"
#include "../encryption/compile_and_runtime.h"

namespace threading
{
	using fn_thread_callback = void(__stdcall*)(void* arg);

	struct thread_creation_info
	{
		_pvoid_enc handle = nullptr;
		unsigned long thread_id = 0;
		encryption::encrypted_block<fn_thread_callback> routine = 0;
		_pvoid_enc argument = 0;
	};

	thread_creation_info create_thread(encryption::encrypted_block<fn_thread_callback> routine, _pvoid_enc arg = nullptr);

}
