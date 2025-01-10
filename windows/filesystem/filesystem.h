#pragma once

#include "../encryption/compile_and_runtime.h"

namespace filesystem
{
	_pvoid_enc read_file(const wchar_t* path);
	_uint_enc get_file_size(const wchar_t* path);
}
