#pragma once

#include "../winapi/wrapper.h"

namespace atomic {
    class critical_section
    {
    public:

        critical_section() {

            if (is_initialized)
                return;

            execute_call(windows::api::ntdll::RtlInitializeCriticalSection, &cs);
            is_initialized = true;
        };

        __forceinline int try_lock() {
            return execute_call<int>(windows::api::ntdll::RtlTryEnterCriticalSection, &cs);
        }

        __forceinline void lock() {
            execute_call(windows::api::ntdll::RtlEnterCriticalSection, &cs);
        }

        __forceinline void release() {

            execute_call(windows::api::ntdll::RtlLeaveCriticalSection, &cs);
        }

        ~critical_section() {
            execute_call(windows::api::ntdll::RtlDeleteCriticalSection, &cs);
        }

    public:
        bool is_initialized = false;
        CRITICAL_SECTION cs = { 0 };
    };

    class interlocked_mutex {
    public:
        interlocked_mutex() : flag(0) {}

        void lock() {
            while (InterlockedExchange(&flag, 1) == 1)
            {

            }
        }

        bool try_lock() {
            return InterlockedExchange(&flag, 1) == 0;
        }

        void release() {
            InterlockedExchange(&flag, 0);
        }

    private:
        LONG flag;
    };

    template<class lock>
    class unique_lock
    {
    public:
        unique_lock(lock* _section) {
            lock_object = _section;
            lock_object->lock();
        }

        ~unique_lock() {
            lock_object->release();
        }
    private:
        lock* lock_object;
    };

    template<class t>
    class shared_variable : public interlocked_mutex {
    public:
        shared_variable() {
            unique_lock lock_guard(this);
            _zeromemory(&data, sizeof(t));
        }

        shared_variable(const t& value) {
            unique_lock lock_guard(this);
            _memcpy(&data, &value, sizeof(t));
        }

        shared_variable(const shared_variable<t>& other) {
            if (this != &other) {
                unique_lock lock_guard_this(this);
                unique_lock lock_guard_other(&other);
                _memcpy(&data, &other.data, sizeof(t));
            }
        }

        shared_variable(shared_variable<t>&& other) noexcept {
            unique_lock lock_guard(this);
            data = std::move(other.data);
        }

        shared_variable(std::initializer_list<t> init_list) {
            unique_lock lock_guard(this);
            data = t(init_list);
        }

        shared_variable<t>& operator=(const shared_variable<t>& other) {
            if (this != &other) {
                unique_lock lock_guard_this(this);
                unique_lock lock_guard_other(&other);
                _memcpy(&data, &other.data, sizeof(t));
            }
            return *this;
        }

        shared_variable<t>& operator=(shared_variable<t>&& other) noexcept {
            if (this != &other) {
                unique_lock lock_guard(this);
                data = std::move(other.data);
            }
            return *this;
        }

        shared_variable<t>& operator=(const t& value) noexcept {
            unique_lock lock_guard(this);
            _memcpy(&data, &value, sizeof(t));
            return *this;
        }


        t get() {
            t out;
            unique_lock lock_guard(this);
            _memcpy(&out, &data, sizeof(t));
            return out;
        }

        void set(const t& value) {
            unique_lock lock_guard(this);
            _memcpy(&data, &value, sizeof(t));
        }

        ~shared_variable() = default;

    private:
        t data;
    };
}
