#pragma once
#include "../common.h"
#include "../winapi/wrapper.h"
#include "../encryption/compile_and_runtime.h"

namespace cert
{
    _bool_enc is_present_in_cat(const wchar_t* filePath);
    _bool_enc is_digitally_signed(const wchar_t* filePath);
}