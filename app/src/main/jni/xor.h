#pragma once
// xor.h — single header, easy string obfuscation for C++ (.so safe)
// Usage:
//   #include "xor.h"
//   const char* url = XOR("https://example.com/api");
//   printf("%s\n", XOR("hello"));
//   std::string s = std::string(XOR("secret"));
//
// NOTE:
//  - C++14 or newer chahiye (NDK default C++17/20 ok hai).
//  - Release build me compile karo (-O2 / -Os) taaki plaintext .rodata me na rahe.
//  - lowercase xor("...") possible NAHI hai kyunki `xor` C++ me keyword hai (^ ka alias).
//    Isliye UPPERCASE XOR("...") use karo.
//  - Har string ki key alag + har build me alag (no fixed key).
//  - `strings app.so | grep "tumhari_string"` karke verify karo — milni nahi chahiye.

#if !defined(__cplusplus)
#error "xor.h: C++ chahiye. .c file ko .cpp rename karke g++ se compile karo. Pure C me compile-time obfuscation possible nahi hai."
#endif

#if __cplusplus < 201402L
#error "xor.h: C++14 ya newer chahiye. CMake me set(CMAKE_CXX_STANDARD 17) karo."
#endif

#include <cstddef>
#include <cstdint>

#if defined(__GNUC__) || defined(__clang__)
#define XOR_H_NOINLINE __attribute__((noinline))
#else
#if defined(_MSC_VER)
#define XOR_H_NOINLINE __declspec(noinline)
#else
#define XOR_H_NOINLINE
#endif
#endif

namespace xor_impl {

// FNV-1a hash — __TIME__ ko seed banane ke liye (har build me alag key)
constexpr std::uint32_t fnv1a(const char* s, unsigned n) {
  std::uint32_t h = 2166136261u;
  for (unsigned i = 0; i < n; ++i) {
    h ^= (std::uint8_t)s[i];
    h *= 16777619u;
  }
  return h;
}

// Har call-site ke liye unique seed: __TIME__ (har build alag) + __COUNTER__ + __LINE__
constexpr std::uint32_t make_seed(int counter, int line) {
  // __TIME__ format "HH:MM:SS" = 8 chars
  return fnv1a(__TIME__, 8) ^ (std::uint32_t)(counter * 0x9E3779B1u) ^
         (std::uint32_t)(line * 0x85EBCA6Bu) ^ 0xC2B2AE35u;
}

// Per-character keystream — kabhi 0 nahi (0 hota to char visible reh jata)
constexpr std::uint8_t keystream(std::uint32_t seed, std::size_t i) {
  std::uint32_t x = seed + (std::uint32_t)(i * 0x9E3779B1u);
  x ^= x >> 16;
  x *= 0x7FEB352Du;
  x ^= x >> 15;
  x *= 0x846CA68Bu;
  x ^= x >> 16;
  x += (std::uint32_t)(i * 0x2D358854u);
  return (std::uint8_t)((x % 255u) + 1u);  // 1..255
}

template <std::size_t N>
struct Holder {
  std::uint32_t seed;
  char data[N];
};

// Compile-time encryption (constexpr → plaintext .so me store nahi hota)
template <std::size_t N>
constexpr Holder<N> encrypt(const char (&s)[N], std::uint32_t seed) {
  Holder<N> h{seed, {}};
  for (std::size_t i = 0; i < N; ++i) {
    h.data[i] = (char)(s[i] ^ (char)keystream(seed, i));
  }
  return h;
}

// Runtime decryption — NOINLINE + memory barrier taaki compiler
// plaintext ko wapas .rodata me fold na kar de.
template <std::size_t N>
XOR_H_NOINLINE const char* decrypt_copy(const Holder<N>& h, char* buf) {
  for (std::size_t i = 0; i < N; ++i) {
    buf[i] = (char)(h.data[i] ^ (char)keystream(h.seed, i));
  }
#if defined(__GNUC__) || defined(__clang__)
  __asm__ volatile("" : "+m"(*(char (*)[N])buf) : : "memory");
#endif
  return buf;
}

}  // namespace xor_impl

// Main macro — function ke andar use karo (global initializer me mat use karo).
// Static encrypted bytes shared, thread_local buffer per-thread → thread-safe,
// har call par fresh decrypt (double-decrypt bug nahi).
#define XOR(s)                                                               \
  ([]{                                                                       \
    static constexpr auto xor_enc__ =                                        \
        ::xor_impl::encrypt(s, ::xor_impl::make_seed(__COUNTER__, __LINE__)); \
    static thread_local char xor_buf__[sizeof(s)];                           \
    return ::xor_impl::decrypt_copy(xor_enc__, xor_buf__);                    \
  }())

// Aliases (same kaam, jo naam pasand ho)
#define XORSTR(s) XOR(s)
#define XSTR(s) XOR(s)
#define OBF(s) XOR(s)
#define CRYPT(s) XOR(s)

// std::string chahiye to: std::string(XOR("secret"))
