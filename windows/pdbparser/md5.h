#pragma once
#include "../crt/crt.h"
#include "../crt/sec_string.h"

namespace pdb_parser
{
	secure_string md5(PVOID buffer, ULONG bufferLen);
}
