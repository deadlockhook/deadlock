#pragma once

#include "crt.h"
#include <Windows.h>
#include <vector>
template<typename T>
class secure_vector {
public:
    secure_vector() = default;
    secure_vector(std::initializer_list<T> init) : vec_(init) {}
    ~secure_vector() {
        clear();
    }

    secure_vector(size_t initial_size) : vec_(initial_size) {}

    secure_vector(const secure_vector& other) : vec_(other.vec_) {}
    secure_vector(secure_vector&& other) noexcept : vec_(std::move(other.vec_)) {
        other.clear_secure();
    }

    secure_vector& operator=(const secure_vector& other) {
        if (this != &other) {
            clear_secure();
            vec_ = other.vec_;
        }
        return *this;
    }

    secure_vector& operator=(secure_vector&& other) noexcept {
        if (this != &other) {
            clear_secure();
            vec_ = std::move(other.vec_);
            other.clear_secure();
        }
        return *this;
    }

    T& operator[](size_t pos) { return vec_[pos]; }
    const T& operator[](size_t pos) const { return vec_[pos]; }
    size_t size() const { return vec_.size(); }
    bool empty() const { return vec_.empty(); }
    void push_back(const T& value) { vec_.push_back(value); }
    void push_back(T&& value) { vec_.push_back(std::move(value)); }
    template<typename... Args>
    T& emplace_back(Args&&... args) { return vec_.emplace_back(std::forward<Args>(args)...); }
    void pop_back() {
        if (!vec_.empty()) {
            secure_clear_element(vec_.size() - 1);
            vec_.pop_back();
        }
    }

    T& at(size_t sizeIndex) {
        return vec_.at(sizeIndex);
    }

    void push_front(const T& value) { vec_.insert(vec_.begin(), value); }
    template<typename... Args>
    void emplace_front(Args&&... args) { vec_.emplace(vec_.begin(), std::forward<Args>(args)...); }
    void pop_front() {
        if (!vec_.empty()) {
            secure_clear_element(0);
            vec_.erase(vec_.begin());
        }
    }

    T* data() {
        return vec_.data();
    }

    void clear() {
        clear_secure();
        vec_.clear();
    }

    void resize(size_t new_size) {
        if (new_size < vec_.size()) {
            for (size_t i = new_size; i < vec_.size(); ++i) {
                secure_clear_element(i);
            }
        }
        vec_.resize(new_size);
    }

    typename std::vector<T>::iterator begin() {
        return vec_.begin();
    }

    typename std::vector<T>::const_iterator begin() const {
        return vec_.begin();
    }

    typename std::vector<T>::iterator end() {
        return vec_.end();
    }

    typename std::vector<T>::const_iterator end() const {
        return vec_.end();
    }

    typename std::vector<T>::iterator insert(typename std::vector<T>::const_iterator pos, const T& value) {
        size_t index = std::distance(vec_.cbegin(), pos);
        return vec_.insert(vec_.begin() + index, value);
    }

    typename std::vector<T>::iterator insert(typename std::vector<T>::const_iterator pos, T&& value) {
        size_t index = std::distance(vec_.cbegin(), pos);
        return vec_.insert(vec_.begin() + index, std::move(value));
    }

    typename std::vector<T>::iterator insert(typename std::vector<T>::const_iterator pos, size_t count, const T& value) {
        size_t index = std::distance(vec_.cbegin(), pos);
        return vec_.insert(vec_.begin() + index, count, value);
    }

    template<typename InputIterator>
    typename std::vector<T>::iterator insert(typename std::vector<T>::const_iterator pos, InputIterator first, InputIterator last) {
        size_t index = std::distance(vec_.cbegin(), pos);
        return vec_.insert(vec_.begin() + index, first, last);
    }

    typename std::vector<T>::iterator erase(typename std::vector<T>::const_iterator pos) {
        size_t index = std::distance(vec_.cbegin(), pos);
        secure_clear_element(index);
        return vec_.erase(vec_.begin() + index);
    }

    typename std::vector<T>::iterator erase(typename std::vector<T>::const_iterator first, typename std::vector<T>::const_iterator last) {
        size_t startIndex = std::distance(vec_.cbegin(), first);
        size_t endIndex = std::distance(vec_.cbegin(), last);
        for (size_t i = startIndex; i < endIndex; i++) {
            secure_clear_element(i);
        }
        return vec_.erase(vec_.begin() + startIndex, vec_.begin() + endIndex);
    }

    template<typename T>
    typename std::vector<T>::iterator next(typename std::vector<T>::iterator it, int n = 1) {
        std::advance(it, n);
        return it;
    }

    template<typename T>
    typename std::vector<T>::const_iterator next(typename std::vector<T>::const_iterator it, int n = 1) {
        std::advance(it, n);
        return it;
    }

private:
    std::vector<T> vec_;
     void clear_secure() {
        for (size_t i = 0; i < vec_.size(); ++i) {
            secure_clear_element(i);
        }
    }
    void secure_clear_element(size_t index) {
        if constexpr (std::is_integral<T>::value || std::is_floating_point<T>::value) {
            volatile T* p = &vec_[index];
            _memset((void*)p, 0, sizeof(T));
        }
    }
};
