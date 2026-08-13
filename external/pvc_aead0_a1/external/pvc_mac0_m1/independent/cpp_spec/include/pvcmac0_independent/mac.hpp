#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace pvcmac0_independent {

// Independent specification implementation of the PVC-MAC-0 wrapper.
// This code intentionally does not include or link the canonical pvc_mac0
// wrapper. Both implementations share only the frozen PVC-PRF-1 C1 primitive.
using Key256 = std::array<std::uint8_t, 32>;
using FullTag256 = std::array<std::uint8_t, 32>;

enum class TagSize : std::uint8_t {
    Bits128 = 16,
    Bits192 = 24,
    Bits256 = 32,
};

[[nodiscard]] constexpr std::size_t tag_size_bytes(TagSize size) noexcept {
    return static_cast<std::size_t>(size);
}

[[nodiscard]] bool is_supported_tag_size(std::size_t bytes) noexcept;
[[nodiscard]] TagSize tag_size_from_bytes(std::size_t bytes);

[[nodiscard]] std::vector<std::uint8_t> frame_message(
    std::span<const std::uint8_t> context,
    std::span<const std::uint8_t> message,
    TagSize tag_size);

[[nodiscard]] FullTag256 compute_full_output(
    const Key256& key,
    std::span<const std::uint8_t> context,
    std::span<const std::uint8_t> message,
    TagSize tag_size);

[[nodiscard]] std::vector<std::uint8_t> compute_tag(
    const Key256& key,
    std::span<const std::uint8_t> context,
    std::span<const std::uint8_t> message,
    TagSize tag_size);

[[nodiscard]] bool verify_tag(
    const Key256& key,
    std::span<const std::uint8_t> context,
    std::span<const std::uint8_t> message,
    std::span<const std::uint8_t> supplied_tag);

} // namespace pvcmac0_independent
