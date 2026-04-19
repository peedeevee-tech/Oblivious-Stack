#pragma once

#include <cstdint>
#include <random>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>
#include <ostream>

/*
 * Local share model for protocol validation.
 *
 * This is NOT a secure distributed implementation.
 * It models the representation of secret shares locally so that the
 * oblivious stack protocol can be exercised end-to-end without network code.
 *
 * We use two-party style additive and XOR shares only as a local abstraction:
 *   - Additive: secret = s0 + s1   (mod 2^64 arithmetic of uint64_t)
 *   - XOR:      secret = s0 ^ s1
 *
 * The runtime stores both share pieces locally for testing. This makes
 * reconstruction straightforward and keeps the code self-contained.
 */

namespace local_mpc {

inline uint64_t random_u64() {
    static thread_local std::mt19937_64 gen(std::random_device{}());
    static std::uniform_int_distribution<uint64_t> dist;
    return dist(gen);
}

template<typename T>
struct AdditiveShare {
    static_assert(std::is_integral_v<T>, "AdditiveShare requires integral type");

    T left{};
    T right{};

    AdditiveShare() = default;
    AdditiveShare(T l, T r) : left(l), right(r) {}

    AdditiveShare operator+(const AdditiveShare& other) const {
        return AdditiveShare(
            static_cast<T>(left + other.left),
            static_cast<T>(right + other.right)
        );
    }

    AdditiveShare operator-(const AdditiveShare& other) const {
        return AdditiveShare(
            static_cast<T>(left - other.left),
            static_cast<T>(right - other.right)
        );
    }

    AdditiveShare& operator+=(const AdditiveShare& other) {
        left = static_cast<T>(left + other.left);
        right = static_cast<T>(right + other.right);
        return *this;
    }

    AdditiveShare& operator-=(const AdditiveShare& other) {
        left = static_cast<T>(left - other.left);
        right = static_cast<T>(right - other.right);
        return *this;
    }
};

template<typename T>
struct XorShare {
    static_assert(std::is_integral_v<T>, "XorShare requires integral type");

    T left{};
    T right{};

    XorShare() = default;
    XorShare(T l, T r) : left(l), right(r) {}

    XorShare operator^(const XorShare& other) const {
        return XorShare(
            static_cast<T>(left ^ other.left),
            static_cast<T>(right ^ other.right)
        );
    }

    XorShare& operator^=(const XorShare& other) {
        left = static_cast<T>(left ^ other.left);
        right = static_cast<T>(right ^ other.right);
        return *this;
    }
};

template<typename T>
inline AdditiveShare<T> share_secret_additive(T secret) {
    static_assert(std::is_integral_v<T>, "share_secret_additive requires integral type");
    T s0 = static_cast<T>(random_u64());
    T s1 = static_cast<T>(secret - s0);
    return AdditiveShare<T>(s0, s1);
}

template<typename T>
inline XorShare<T> share_secret_xor(T secret) {
    static_assert(std::is_integral_v<T>, "share_secret_xor requires integral type");
    T s0 = static_cast<T>(random_u64());
    T s1 = static_cast<T>(s0 ^ secret);
    return XorShare<T>(s0, s1);
}

template<typename T>
inline T reconstruct(const AdditiveShare<T>& s) {
    return static_cast<T>(s.left + s.right);
}

template<typename T>
inline T reconstruct(const XorShare<T>& s) {
    return static_cast<T>(s.left ^ s.right);
}

template<typename T>
inline std::ostream& operator<<(std::ostream& os, const AdditiveShare<T>& s) {
    os << "(" << s.left << ", " << s.right << ")";
    return os;
}

template<typename T>
inline std::ostream& operator<<(std::ostream& os, const XorShare<T>& s) {
    os << "(" << s.left << ", " << s.right << ")";
    return os;
}

template<typename T>
struct AdditiveShareVector {
    static_assert(std::is_integral_v<T>, "AdditiveShareVector requires integral type");

    std::vector<AdditiveShare<T>> vals;

    AdditiveShareVector() = default;
    explicit AdditiveShareVector(std::vector<AdditiveShare<T>> v) : vals(std::move(v)) {}

    std::size_t size() const { return vals.size(); }

    const AdditiveShare<T>& operator[](std::size_t i) const { return vals[i]; }
    AdditiveShare<T>& operator[](std::size_t i) { return vals[i]; }
};

} // namespace local_mpc
