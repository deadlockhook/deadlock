#pragma once
#include "../common.h"
#include "../crt/crt.h"
#include "../crt/sec_string.h"
#include "../crt/sec_vector.h"
#include "../typedefs.h"
#include "encryption/enc_string.h"
#include "encryption/compile_and_runtime.h"

#include "../thirdparty/curl/curl.h"

#pragma comment(lib, "../windows/thirdparty/curl/libcurl_a.lib") 

#pragma comment(lib, "Dwmapi.lib")   
#pragma comment(lib, "wininet.lib")  
#pragma comment(lib, "Normaliz.lib")
#pragma comment(lib, "Ws2_32.lib")   
#pragma comment(lib, "Wldap32.lib")  
#pragma comment(lib, "Crypt32.lib")  
#pragma comment(lib, "advapi32.lib") 

#ifdef DL_ENABLE_VIRTUALIZATION
#pragma comment(lib, "C:/Dev/Virtualizer/Lib/x86_x64/windows/COFF/VirtualizerSDK64.lib") 
#endif

//C:\Development\deadlock\windows\thirdparty\curl\

namespace net
{
	secure_string send_request(const secure_string& url);
	secure_string send_request(const secure_string& szURL, const secure_string& post_fields);
	secure_string net_send_request_post(const secure_string& szURL, const secure_string& szPostFields);
	void net_download_file(secure_string FileUrl, secure_vector<_char>& BufferOut);
	_ulonglong_enc net_download_file_to_disk(secure_string url, secure_string path_on_disk);
}
