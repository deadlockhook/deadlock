#pragma once
#include <Windows.h>
#include <string>
#include "crt.h"

class secure_string : public std::string {
public:
    using std::string::string;

    explicit secure_string(const std::string& s) : std::string(s) {}
    secure_string(std::string&& s) noexcept : std::string(std::move(s)) {}

    secure_string(const secure_string& other) : std::string(other) {}
    secure_string(secure_string&& other) noexcept : std::string(std::move(other)) {}

    secure_string& operator=(const secure_string& other) {
        clear_secure();
        std::string::operator=(other);
        return *this;
    }

    secure_string& operator=(secure_string&& other) noexcept {
        clear_secure();
        std::string::operator=(std::move(other));
        return *this;
    }

    secure_string& operator=(const std::string& str) {
        clear_secure();
        std::string::operator=(str);
        return *this;
    }

    secure_string& operator=(std::string&& str) noexcept {
        clear_secure();
        std::string::operator=(std::move(str));
        return *this;
    }


    secure_string& operator=(const char* s) {
        clear_secure();
        std::string::operator=(s);
        return *this;
    }

    ~secure_string() {
        clear_secure();
    }

    secure_string substr(size_t pos = 0, size_t len = std::string::npos) const {
        return secure_string(std::string::substr(pos, len));
    }

    void clear_secure() {
        volatile char* p = const_cast<char*>(this->data());
        _memset((void*)p, 0, this->size());
        this->clear();
    }

};

class secure_wide_string : public std::wstring {
public:
    using std::wstring::wstring;

    explicit secure_wide_string(const std::wstring& s) : std::wstring(s) {}
    secure_wide_string(std::wstring&& s) noexcept : std::wstring(std::move(s)) {}

    secure_wide_string(const secure_wide_string& other) : std::wstring(other) {}
    secure_wide_string(secure_wide_string&& other) noexcept : std::wstring(std::move(other)) {}

    secure_wide_string& operator=(const secure_wide_string& other) {
        clear_secure();
        std::wstring::operator=(other);
        return *this;
    }

    secure_wide_string& operator=(secure_wide_string&& other) noexcept {
        clear_secure();
        std::wstring::operator=(std::move(other));
        return *this;
    }

    secure_wide_string& operator=(const std::wstring& str) {
        clear_secure();
        std::wstring::operator=(str);
        return *this;
    }

    secure_wide_string& operator=(std::wstring&& str) noexcept {
        clear_secure();
        std::wstring::operator=(std::move(str));
        return *this;
    }


    secure_wide_string& operator=(const wchar_t* s) {
        clear_secure();
        std::wstring::operator=(s);
        return *this;
    }

    ~secure_wide_string() {
        clear_secure();
    }

    secure_wide_string substr(size_t pos = 0, size_t len = std::wstring::npos) const {
        return secure_wide_string(std::wstring::substr(pos, len));
    }

    void clear_secure() {
        volatile wchar_t* p = const_cast<wchar_t*>(this->data());
        _memset((void*)p, 0, this->size() * sizeof(wchar_t));
        this->clear();
    }

};


inline secure_string operator+(const secure_string& lhs, const secure_string& rhs) {
    secure_string result = lhs;
    result += rhs;
    return result;
}

inline secure_string operator+(const char* lhs, const secure_string& rhs) {
    secure_string result(lhs);
    result += rhs;
    return result;
}

inline secure_string operator+(const secure_string& lhs, const char* rhs) {
    secure_string result(lhs);
    result += rhs;
    return result;
}


inline secure_wide_string operator+(const secure_wide_string& lhs, const secure_wide_string& rhs) {
    secure_wide_string result = lhs;
    result += rhs;
    return result;
}

inline secure_wide_string operator+(const wchar_t* lhs, const secure_wide_string& rhs) {
    secure_wide_string result(lhs);
    result += rhs;
    return result;
}

inline secure_wide_string operator+(const secure_wide_string& lhs, const wchar_t* rhs) {
    secure_wide_string result(lhs);
    result += rhs;
    return result;
}