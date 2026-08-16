#pragma once

// Minimal bounded models for the subset of the C++ standard library used by
// Candidate A1. They let CBMC parse the unmodified C++20 implementation with
// its C++11 frontend. These are verification models, not replacement runtime
// containers.

extern "C" void __CPROVER_assert(bool condition, const char* description);

#ifndef PVC_CBMC_VECTOR_CAPACITY
#define PVC_CBMC_VECTOR_CAPACITY 80U
#endif

namespace std {

typedef unsigned long size_t;
typedef unsigned char uint8_t;
typedef unsigned long uint64_t;

template <typename T, size_t N>
struct array {
    T elements[N];

    array() {}
    array(const array& other) {
        for (size_t index = 0U; index < N; ++index) elements[index] = other.elements[index];
    }
    array& operator=(const array& other) {
        for (size_t index = 0U; index < N; ++index) elements[index] = other.elements[index];
        return *this;
    }
    array(T value0,
          T value1,
          T value2,
          T value3,
          T value4,
          T value5,
          T value6,
          T value7,
          T value8,
          T value9) {
        __CPROVER_assert(N == 10U, "ten-element initializer matches array extent");
        elements[0U] = value0;
        elements[1U] = value1;
        elements[2U] = value2;
        elements[3U] = value3;
        elements[4U] = value4;
        elements[5U] = value5;
        elements[6U] = value6;
        elements[7U] = value7;
        elements[8U] = value8;
        elements[9U] = value9;
    }

    T* begin() { return elements; }
    const T* begin() const { return elements; }
    T* end() { return elements + N; }
    const T* end() const { return elements + N; }
    T& operator[](size_t index) {
        __CPROVER_assert(index < N, "std::array index is in bounds");
        return elements[index];
    }
    const T& operator[](size_t index) const {
        __CPROVER_assert(index < N, "std::array index is in bounds");
        return elements[index];
    }
};

template <typename T>
class vector {
public:
    typedef T* iterator;
    typedef const T* const_iterator;

    vector() : size_(0U), capacity_(0U) {}

    vector(const vector& other) : size_(other.size_), capacity_(other.capacity_) {
        for (size_t index = 0U; index < size_; ++index) elements_[index] = other.elements_[index];
    }

    vector& operator=(const vector& other) {
        size_ = other.size_;
        capacity_ = other.capacity_;
        for (size_t index = 0U; index < size_; ++index) elements_[index] = other.elements_[index];
        return *this;
    }

    explicit vector(size_t size) : size_(size), capacity_(size) {
        __CPROVER_assert(size <= PVC_CBMC_VECTOR_CAPACITY,
                         "bounded vector construction fits the model");
    }

    size_t size() const { return size_; }
    bool empty() const { return size_ == 0U; }

    iterator begin() { return elements_; }
    const_iterator begin() const { return elements_; }
    iterator end() { return elements_ + size_; }
    const_iterator end() const { return elements_ + size_; }

    void reserve(size_t requested) {
        __CPROVER_assert(requested <= PVC_CBMC_VECTOR_CAPACITY,
                         "bounded reserve fits the model");
        if (requested > capacity_) capacity_ = requested;
    }

    void push_back(const T& value) {
        // The A1 frame writers reserve their exact final size. Requiring the
        // write to remain inside that guarantee checks their size arithmetic.
        __CPROVER_assert(size_ < capacity_,
                         "frame write stays inside reserved capacity");
        elements_[size_] = value;
        ++size_;
    }

    void insert(iterator position, const_iterator first, const_iterator last) {
        __CPROVER_assert(position == end(), "A1 only appends to its frames");
        while (first != last) {
            push_back(*first);
            ++first;
        }
    }

    T& operator[](size_t index) {
        __CPROVER_assert(index < size_, "std::vector index is in bounds");
        return elements_[index];
    }

    const T& operator[](size_t index) const {
        __CPROVER_assert(index < size_, "std::vector index is in bounds");
        return elements_[index];
    }

private:
    T elements_[PVC_CBMC_VECTOR_CAPACITY];
    size_t size_;
    size_t capacity_;
};

template <typename T>
class span {
public:
    span() : data_(0), size_(0U) {}
    span(T* data, size_t size) : data_(data), size_(size) {}

    template <typename U>
    span(const vector<U>& value) : data_(value.begin()), size_(value.size()) {}

    size_t size() const { return size_; }
    bool empty() const { return size_ == 0U; }
    T* begin() const { return data_; }
    T* end() const { return data_ + size_; }
    T& operator[](size_t index) const {
        __CPROVER_assert(index < size_, "std::span index is in bounds");
        return data_[index];
    }

private:
    T* data_;
    size_t size_;
};

struct nullopt_t {};
static const nullopt_t nullopt = nullopt_t();

template <typename T>
class optional {
public:
    optional() : engaged_(false), value_() {}
    optional(nullopt_t) : engaged_(false), value_() {}
    optional(const T& value) : engaged_(true), value_(value) {}

    operator bool() const { return engaged_; }
    bool has_value() const { return engaged_; }
    T& operator*() { return value_; }
    const T& operator*() const { return value_; }
    T* operator->() { return &value_; }
    const T* operator->() const { return &value_; }

private:
    bool engaged_;
    T value_;
};

class string {
public:
    string(const char*) {}
};

inline string operator+(const string&, const char*) { return string(""); }

class invalid_argument {
public:
    invalid_argument(const char*) {}
};

class length_error {
public:
    length_error(const char*) {}
    length_error(const string&) {}
};

template <typename T>
struct numeric_limits {
    static T max() { return static_cast<T>(~static_cast<T>(0)); }
};

template <typename T>
T min(T left, T right) {
    return right < left ? right : left;
}

} // namespace std
