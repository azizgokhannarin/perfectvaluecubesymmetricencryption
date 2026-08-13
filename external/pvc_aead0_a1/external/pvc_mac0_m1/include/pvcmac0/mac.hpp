#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace pvcmac0 {

// PVC-MAC-0 Candidate M1 / v0.2.0 is frozen experimental research software. It is not
// production cryptography and carries no proven security claim.
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

// Canonical injective input encoding for PVC-MAC-0. Exposed to support
// independent implementations and byte-exact audit tooling.
[[nodiscard]] std::vector<std::uint8_t> frame_message(
    std::span<const std::uint8_t> context,
    std::span<const std::uint8_t> message,
    TagSize tag_size);

[[nodiscard]] std::vector<std::uint8_t> compute_tag(
    const Key256& key,
    std::span<const std::uint8_t> context,
    std::span<const std::uint8_t> message,
    TagSize tag_size);

// Comparison time is independent of tag byte contents. Tag length is public
// and invalid lengths are rejected before C1 evaluation.
[[nodiscard]] bool verify_tag(
    const Key256& key,
    std::span<const std::uint8_t> context,
    std::span<const std::uint8_t> message,
    std::span<const std::uint8_t> supplied_tag);

} // namespace pvcmac0
