#pragma once
#include "../crt/crt.h"
#include <type_traits>

//credits : https://github.com/skadro-official/skCrypter
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
namespace skc
{
	template<class _Ty>
	using clean_type = typename std::remove_const_t<std::remove_reference_t<_Ty>>;

	template <int _size, char _key1, char _key2, typename T>
	class E_CRYPTer
	{
	public:
		__forceinline constexpr E_CRYPTer(T* data)
		{
			crypt(data);
		}

		__forceinline T* get()
		{
			return _storage;
		}

		__forceinline int size() 
		{
			return _size;
		}

		__forceinline  char key()
		{
			return _key1;
		}

		__forceinline  T* encrypt()
		{
			if (!isEncrypted())
				crypt(_storage);

			return _storage;
		}

		__forceinline  T* decrypt()
		{
			if (isEncrypted())
				crypt(_storage);

			return _storage;
		}

		__forceinline bool isEncrypted()
		{
			return _storage[_size - 1] != 0;
		}

		__forceinline void clear()
		{
			for (int i = 0; i < _size; i++)
			{
				_storage[i] = 0;
			}
		}

		__forceinline operator T* ()
		{
			decrypt();

			return _storage;
		}

	private:
		__forceinline constexpr void crypt(T* data)
		{
			for (int i = 0; i < _size; i++)
			{
				_storage[i] = data[i] ^ (_key1 + i % (1 + _key2));
			}

		}

		T _storage[_size]{};
	};
}

#define ENCRYPT_STRING(str) E_CRYPT_key(str, __TIME__[1], __TIME__[7])
#define E_CRYPT_key(str, key1, key2) []() { \
			constexpr static auto crypted = skc::E_CRYPTer \
				<sizeof(str) / sizeof(str[0]), key1, key2, skc::clean_type<decltype(str[0])>>((skc::clean_type<decltype(str[0])>*)str); \
					return crypted; }()

namespace encryption {

	inline _ulonglong initial_xor_key = ' ';

	constexpr _ulonglong compile_time_hash(const _char* str, _ulonglong length) {
		_ulonglong hash = 0xcbf29ce484222325;
		_ulonglong prime = 0x100000001b3;

		for (_ulonglong i = 0; i < length; ++i) {
			hash ^= static_cast<_ulonglong>(str[i]);
			hash *= prime;
		}

		return hash;
	}

	constexpr _char create_xor_key() {
		constexpr _ulonglong line_hash = compile_time_hash(TOSTRING(__LINE__), sizeof(TOSTRING(__LINE__)) - 1);
		constexpr _ulonglong file_hash = compile_time_hash(__FILE__, sizeof(__FILE__) - 1);
		constexpr _ulonglong function_hash = compile_time_hash(__FUNCTION__, sizeof(__FUNCTION__) - 1);
		constexpr _ulonglong time_hash = compile_time_hash(__TIME__, sizeof(__TIME__) - 1);
		constexpr _ulonglong combined_hash = line_hash ^ file_hash ^ function_hash ^ time_hash;
		constexpr _char key = static_cast<_char>(combined_hash & 0xFF);
		return key;
	}

	template <int _size, char _key1, char _key2, char _key3, typename T>
	class xor_string
	{
	private:
		T _data[_size]{};
	public:
		__forceinline constexpr xor_string(T* data)
		{
			crypt(data);
		}

		__forceinline  T* decrypt()
		{
			if (is_encrypted())
				crypt(_data);

			return _data;
		}

		__forceinline bool is_encrypted()
		{
			return _data[_size - 1] != 0;
		}

		__forceinline void clear()
		{
			for (int i = 0; i < _size; i++)
			{
				_data[i] = 0;
			}
		}

		__forceinline operator T* ()
		{
			return decrypt();
		}

		__forceinline constexpr void crypt(T* data)
		{
			for (int i = 0; i < _size; i++)
			{
				char key_part1 = (_key1 + i * 3) % 256;
				char key_part2 = (_key2 + (i * i) % 128) % 256;
				char key_part3 = (_key3 + ((i + 1) * (i + 1)) % 64) % 256;
				char key_part4 = ((_key1 ^ _key2) + i * 2) % 256;
				char key_part5 = ((_key2 ^ _key3) + i) % 256;
				char key_part6 = ((_key1 + _key3 + i) ^ _key2) % 256;
				char key_part7 = ((_key3 + i * 5) ^ (_key1 + i * 7)) % 256;
				char key_part8 = ((_key2 + i * 9) ^ (_key3 + i * 11)) % 256;
				char key_part9 = ((_key1 + _key2 + _key3 + i) * (i % 3)) % 256;

				char dynamic_key = ((key_part1 ^ key_part2) + (key_part3 ^ key_part4) - key_part5) ^
					((key_part6 + key_part7) ^ (key_part8 - key_part9));

				_data[i] = data[i] ^ dynamic_key;
			}
		}
	};


	__forceinline void initialize() {
		for (_uchar i = 0; i < sizeof(_ulonglong); i++)
			((_uchar*)&initial_xor_key)[i] = static_cast<_uchar>(create_xor_key() * i);
	}

	template <class T, _char encryption_key = sizeof(T)>
	struct encrypted_block {

		encrypted_block()
		{

		}

		encrypted_block(encrypted_block<T>&& Pass)
		{
			_memcpy((void*)memory_block, (void*)Pass.memory_block, sizeof(memory_block));
		}

		encrypted_block(const encrypted_block<T>& Copy)
		{
			_memcpy((void*)memory_block, (void*)Copy.memory_block, sizeof(memory_block));
		}

		encrypted_block(const T& Create)
		{
			store(Create);
		}

		~encrypted_block()
		{

		}

		__forceinline void operator=(const encrypted_block<T, encryption_key>& Copy)
		{
			_memcpy((void*)memory_block, (void*)Copy.memory_block, sizeof(memory_block));
		}

		__forceinline void operator=(const T& Create)
		{
			store(Create);
		}

		__forceinline bool operator!=(const T& Right)
		{
			T Decrypted = get_decrypted();
			return !_memequal((void*)&Decrypted, (void*)&Right, sizeof(T));
		}

		__forceinline bool operator==(const T& Right)
		{
			return !(this != Right);
		}

		__forceinline T get_decrypted()
		{
			T decrypted;
			_char memory_block_dcr[sizeof(T)];
			_memcpy((void*)memory_block_dcr, (void*)memory_block, sizeof(memory_block));

			encrypt_decrypt(memory_block_dcr);

			size_t size_to_decrypt = sizeof(T) - 1;
			while (size_to_decrypt >= 0)
			{
				((_char*)&decrypted)[size_to_decrypt] = ((_char*)memory_block_dcr)[size_to_decrypt];

				if (size_to_decrypt == 0)
					break;

				size_to_decrypt -= 1;
			}

			return decrypted;
		}

		__forceinline T get_encrypted()
		{

			T Decrypted;
			_char memory_block_dcr[sizeof(T)];
			_memcpy((void*)memory_block_dcr, (void*)memory_block, sizeof(memory_block));

			size_t size_to_decrypt = sizeof(T) - 1;
			while (size_to_decrypt >= 0)
			{
				((_char*)&Decrypted)[size_to_decrypt] = ((_char*)memory_block_dcr)[size_to_decrypt];

				if (size_to_decrypt == 0)
					break;

				size_to_decrypt -= 1;
			}

			return Decrypted;
		}

	private:

		__forceinline void store(const T& Copy) {

			_memcpy((void*)memory_block, (void*)&Copy, sizeof(T));

			size_t sizeToStore = sizeof(T) - 1;
			while (sizeToStore >= 0)
			{
				memory_block[sizeToStore] = (_char)(((_char*)&Copy)[sizeToStore]);

				if (sizeToStore == 0)
					break;

				sizeToStore -= 1;
			}

			encrypt_decrypt(memory_block);
		}

		__forceinline void encrypt_decrypt(char* Mem) {

			size_t size_to_encrypt = sizeof(T) - 1;

			while (size_to_encrypt >= 0)
			{
				Mem[size_to_encrypt] = Mem[size_to_encrypt] ^ (encryption_key + ((_uchar*)&initial_xor_key)[size_to_encrypt % 7]);

				if (size_to_encrypt == 0)
					break;

				size_to_encrypt -= 1;
			}
		}

	public:
		_char padding1[(((5) + 1)) + sizeof(T) * 2];
		_char memory_block[sizeof(T)];
		_char padding2[(((7) + 1)) + sizeof(T) * 2];
	};

}

typedef encryption::encrypted_block<char> _char_enc;
typedef encryption::encrypted_block<wchar_t> _wchar_enc;
typedef encryption::encrypted_block<int> _bool_enc;
typedef encryption::encrypted_block<short> _short_enc;
typedef encryption::encrypted_block<int> _int_enc;
typedef encryption::encrypted_block<long> _long_enc;
typedef encryption::encrypted_block<long long> _longlong_enc;

typedef encryption::encrypted_block<unsigned char> _uchar_enc;
typedef encryption::encrypted_block<unsigned short> _ushort_enc;
typedef encryption::encrypted_block<unsigned int> _uint_enc;
typedef encryption::encrypted_block<unsigned long> _ulong_enc;
typedef encryption::encrypted_block<unsigned long long> _ulonglong_enc;
typedef encryption::encrypted_block<void*> _pvoid_enc;
typedef encryption::encrypted_block<const wchar_t*> _lpcwstr_enc;
typedef encryption::encrypted_block<const char*> _lpcstr_enc;

