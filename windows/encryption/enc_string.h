#pragma once
#include "../crt/crt.h"
#include "../crt/sec_string.h"
#include "../crt/sec_vector.h"
#include "compile_and_runtime.h"

namespace encryption {

	class encrypted_string
	{
	public:

		encrypted_string()
		{

		}

		encrypted_string(const char* _String)
		{
			allocate_from_buffer(_String);
		}

		encrypted_string(char* _String)
		{
			allocate_from_buffer((const char*)_String);
		}

		void operator=(const char* _String)
		{
			allocate_from_buffer((const char*)_String);
		}

		void operator=(char* _String)
		{
			allocate_from_buffer((const char*)_String);
		}

		encrypted_string(secure_string& _String)
		{
			allocate_from_buffer((const char*)_String.c_str());
		}

		void operator=(secure_string& _String)
		{
			allocate_from_buffer((const char*)_String.c_str());
		}

		encrypted_string(const encrypted_string& other) {
			String = other.String;
		}

		encrypted_string& operator=(const encrypted_string& other) {

			if (this != &other)
				String = other.String;

			return *this;
		}

		encrypted_string(encrypted_string&& other) noexcept
		{
			if (this != &other) {
				String = _move(other.String);
			}
		}

		encrypted_string& operator=(encrypted_string&& other) noexcept {
			if (this != &other) {
				String.clear();
				String = _move(other.String);
			}
			return *this;
		}


		secure_string get_string() {

			if (!String.size())
				return secure_string();

			secure_string  StringOut;

			size_t sizeLength = String.size();

			while (sizeLength)
			{
				StringOut += static_cast<const char>(String[String.size() - sizeLength].get_decrypted());

				--sizeLength;
			}

			return StringOut;
		}

		size_t get_length() { return String.size(); }

	private:

		void allocate_from_buffer(const char* _String) {

			String.clear();

			size_t sizeLength = _strlen(_String);
			size_t sizeLengthEx = sizeLength;

			if (!sizeLength)
				return;

			while (sizeLength)
			{
				auto Char = String.emplace_back(_String[sizeLengthEx - sizeLength]);
				--sizeLength;
			}
		}

	private:
		secure_vector<_int_enc> String;
	};


	class encrypted_wide_string
	{
	public:

		encrypted_wide_string()
		{

		}

		encrypted_wide_string(const wchar_t* _String)
		{
			allocate_from_buffer(_String);
		}

		encrypted_wide_string(wchar_t* _String)
		{
			allocate_from_buffer((const wchar_t*)_String);
		}

		void operator=(const wchar_t* _String)
		{
			allocate_from_buffer((const wchar_t*)_String);
		}

		void operator=(wchar_t* _String)
		{
			allocate_from_buffer((const wchar_t*)_String);
		}

		encrypted_wide_string(secure_wide_string& _String)
		{
			allocate_from_buffer((const wchar_t*)_String.c_str());
		}

		void operator=(secure_wide_string& _String)
		{
			allocate_from_buffer((const wchar_t*)_String.c_str());
		}

		encrypted_wide_string(const encrypted_wide_string& other) {
			String = other.String;
		}

		encrypted_wide_string& operator=(const encrypted_wide_string& other) {

			if (this != &other)
				String = other.String;

			return *this;
		}

		encrypted_wide_string(encrypted_wide_string&& other) noexcept
		{
			if (this != &other) {
				String = _move(other.String);
			}
		}

		encrypted_wide_string& operator=(encrypted_wide_string&& other) noexcept {
			if (this != &other) {
				String.clear();
				String = _move(other.String);
			}
			return *this;
		}


		secure_wide_string get_string() {

			if (!String.size())
				return secure_wide_string();

			secure_wide_string  StringOut;

			size_t sizeLength = String.size();

			while (sizeLength)
			{
				StringOut += static_cast<const wchar_t>(String[String.size() - sizeLength].get_decrypted());

				--sizeLength;
			}

			return StringOut;
		}

		size_t get_length() { return String.size(); }

	private:

		void allocate_from_buffer(const wchar_t* _String) {

			String.clear();

			size_t sizeLength = _wcslen(_String);
			size_t sizeLengthEx = sizeLength;

			if (!sizeLength)
				return;

			while (sizeLength)
			{
				auto Char = String.emplace_back(_String[sizeLengthEx - sizeLength]);
				--sizeLength;
			}
		}

	private:
		secure_vector<_int_enc> String;
	};



#pragma optimize( "", off )
	__forceinline void encrypt_decrypt_string(encrypted_string plaintext, encrypted_string& Out) {
		secure_string PlainString = plaintext.get_string();
		secure_string OutString;

		for (_ulonglong Current = 0; Current < PlainString.length(); Current++)
			OutString += PlainString[Current] ^ 2324531443234;

		Out = OutString;

		memset(OutString.data(), 0, OutString.size());
		memset(PlainString.data(), 0, PlainString.size());
	}
#pragma optimize("",on)


}
