#pragma once
#include <array>
#include <optional>
#include <span>
#include <vector>

namespace aes {
constexpr auto block_size = 128 / 8;

using IV = std::array<std::byte, block_size>;

auto encrypt(std::span<const std::byte> key, const IV& iv, std::span<const std::byte> data) -> std::optional<std::vector<std::byte>>;
auto decrypt(std::span<const std::byte> key, const IV& iv, std::span<const std::byte> data) -> std::optional<std::vector<std::byte>>;
} // namespace aes
