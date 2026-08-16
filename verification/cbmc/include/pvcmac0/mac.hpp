#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace pvcmac0 {

typedef std::array<std::uint8_t, 32> Key256;

enum class TagSize : std::uint8_t {
    Bits128 = 16,
    Bits192 = 24,
    Bits256 = 32,
};

std::vector<std::uint8_t> compute_tag(
    const Key256& key,
    const std::vector<std::uint8_t>& context,
    const std::vector<std::uint8_t>& message,
    TagSize tag_size);

bool verify_tag(
    const Key256& key,
    const std::vector<std::uint8_t>& context,
    std::span<const std::uint8_t> message,
    std::span<const std::uint8_t> supplied_tag);

} // namespace pvcmac0
