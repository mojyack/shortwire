#pragma once
#include <cstdint>
#include <optional>

auto print_mac_addr(const uint8_t* addr) -> void;
auto to_inet_addr(const char* str) -> std::optional<uint32_t>;
auto setup_tap_dev(const uint32_t address, const uint16_t mtu) -> std::optional<int>;

inline auto to_inet_addr(const uint8_t a, const uint8_t b, const uint8_t c, const uint8_t d) -> uint32_t {
    return a << 24 | b << 16 | c << 8 | d;
}
