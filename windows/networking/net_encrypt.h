#pragma once
#include "../crt/crt.h"
#include "../crt/sec_string.h"
#include "../crt/sec_vector.h"
#include "../encryption/enc_string.h"
#include "../encryption/compile_and_runtime.h"

#define SODIUM_STATIC 1
#pragma comment(lib, "../windows/thirdparty/sodium/libsodium.lib") 
#include "../windows/thirdparty/sodium/sodium.h"


namespace net
{
	__declspec(noinline) secure_vector<unsigned char> net_base64_decode_ex(const secure_string& encoded_string);
	__declspec(noinline) secure_string net_base64_decode(const secure_string& encoded_string);

	__declspec(noinline) secure_vector<unsigned char> net_base64_encode_ex(const secure_string& encoded_string);
	__declspec(noinline) secure_string net_base64_encode(const secure_string& plain_string);

	__declspec(noinline) secure_string binary_to_hex(secure_vector<unsigned char>& bin);
	__declspec(noinline) secure_vector<unsigned char> hex_to_binary(const secure_string& hex);

	__declspec(noinline) secure_string decrypt(secure_string data, encryption::encrypted_string encrypted_key, encryption::encrypted_string encrypted_iv);
	__declspec(noinline) secure_string encrypt(secure_string data, encryption::encrypted_string encrypted_key, encryption::encrypted_string encrypted_iv);
}
