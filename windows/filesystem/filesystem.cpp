#include "filesystem.h"
#include "../windows/winapi/wrapper.h"
#include "memory/memory.h"

_uint_enc filesystem::get_file_size(const wchar_t* path) {

	HANDLE hFile = execute_call<HANDLE>(windows::api::kernel32::CreateFileW,
		path,
		GENERIC_READ,
		0,
		(LPSECURITY_ATTRIBUTES)nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		(HANDLE)nullptr
	);

	if (hFile == INVALID_HANDLE_VALUE)
		return 0;

	DWORD fileSize = execute_call<DWORD>(windows::api::kernel32::GetFileSize, hFile, NULL);

	if (fileSize == INVALID_FILE_SIZE) {
		execute_call(windows::api::kernel32::CloseHandle, hFile);
		return 0;
	}

	execute_call(windows::api::kernel32::CloseHandle, hFile);

	return fileSize;
}
_pvoid_enc filesystem::read_file(const wchar_t* path) {

	//vm_low_start

		HANDLE hFile = execute_call<HANDLE>(windows::api::kernel32::CreateFileW,
			path,
			GENERIC_READ,
			0,
			(LPSECURITY_ATTRIBUTES)nullptr,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			(HANDLE)nullptr
		);

	if (hFile == INVALID_HANDLE_VALUE)
		return nullptr;

	DWORD fileSize = execute_call<DWORD>(windows::api::kernel32::GetFileSize, hFile, NULL);
	if (fileSize == INVALID_FILE_SIZE) {
		execute_call(windows::api::kernel32::CloseHandle, hFile);
		return nullptr;
	}

	BYTE* buffer = (BYTE*)memory::_malloc(fileSize).get_decrypted();

	if (!buffer) {
		execute_call(windows::api::kernel32::CloseHandle, hFile);
		return nullptr;
	}
	DWORD bytesRead;

	if (!execute_call<BOOL>(windows::api::kernel32::ReadFile, hFile, buffer, fileSize, &bytesRead, (LPOVERLAPPED)nullptr) || bytesRead != fileSize) {
		execute_call(windows::api::kernel32::CloseHandle, hFile);
		memory::_free(buffer);
		return nullptr;
	}

	execute_call(windows::api::kernel32::CloseHandle, hFile);

	//vm_low_end

		return buffer;
}

