#include "pvcmac0_independent/mac.hpp"

#include "pvc1/key_schedule.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>

namespace pvcmac0_independent {
namespace {

constexpr std::array<std::uint8_t, 14> kFixedPrefix{
    0x50U, 0x56U, 0x43U, 0x2DU, 0x4DU, 0x41U, 0x43U,
    0x2DU, 0x30U, 0x00U, 0x01U, 0xC1U, 0x00U, 0x00U,
};
constexpr std::size_t kHeaderBytes = 30U;
constexpr std::size_t kTagOffset = 12U;
constexpr std::size_t kContextLengthOffset = 14U;
constexpr std::size_t kMessageLengthOffset = 22U;

void store_u64_be(std::span<std::uint8_t, 8> destination, std::uint64_t value) {
    for (std::size_t i = 0; i < destination.size(); ++i) {
        const auto shift = static_cast<unsigned>((destination.size() - 1U - i) * 8U);
        destination[i] = static_cast<std::uint8_t>((value >> shift) & 0xFFU);
    }
}

std::uint64_t to_u64_length(std::size_t value) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > static_cast<std::size_t>(std::numeric_limits<std::uint64_t>::max())) {
            throw std::length_error("PVC-MAC-0 independent frame length exceeds u64");
        }
    }
    return static_cast<std::uint64_t>(value);
}

TagSize checked_tag_size(std::size_t bytes) {
    if (bytes == 16U) return TagSize::Bits128;
    if (bytes == 24U) return TagSize::Bits192;
    if (bytes == 32U) return TagSize::Bits256;
    throw std::invalid_argument("PVC-MAC-0 independent tag size must be 16, 24, or 32 bytes");
}

} // namespace

bool is_supported_tag_size(std::size_t bytes) noexcept {
    return bytes == 16U || bytes == 24U || bytes == 32U;
}

TagSize tag_size_from_bytes(std::size_t bytes) {
    return checked_tag_size(bytes);
}

std::vector<std::uint8_t> frame_message(std::span<const std::uint8_t> context,
                                        std::span<const std::uint8_t> message,
                                        TagSize tag_size) {
    const auto tag_bytes = tag_size_bytes(tag_size);
    (void)checked_tag_size(tag_bytes);

    if (context.size() > std::numeric_limits<std::size_t>::max() - kHeaderBytes) {
        throw std::length_error("PVC-MAC-0 independent frame size overflows size_t");
    }
    const auto prefix_and_context = kHeaderBytes + context.size();
    if (message.size() > std::numeric_limits<std::size_t>::max() - prefix_and_context) {
        throw std::length_error("PVC-MAC-0 independent frame size overflows size_t");
    }

    std::vector<std::uint8_t> framed(prefix_and_context + message.size());
    std::copy(kFixedPrefix.begin(), kFixedPrefix.end(), framed.begin());
    framed[kTagOffset] = static_cast<std::uint8_t>(tag_bytes);

    store_u64_be(std::span<std::uint8_t, 8>(framed.data() + kContextLengthOffset, 8U),
                 to_u64_length(context.size()));
    store_u64_be(std::span<std::uint8_t, 8>(framed.data() + kMessageLengthOffset, 8U),
                 to_u64_length(message.size()));

    std::copy(context.begin(), context.end(), framed.begin() + static_cast<std::ptrdiff_t>(kHeaderBytes));
    std::copy(message.begin(), message.end(),
              framed.begin() + static_cast<std::ptrdiff_t>(kHeaderBytes + context.size()));
    return framed;
}

FullTag256 compute_full_output(const Key256& key,
                               std::span<const std::uint8_t> context,
                               std::span<const std::uint8_t> message,
                               TagSize tag_size) {
    const auto framed = frame_message(context, message, tag_size);
    return pvc1::research_keyed_return_output_a2(key, framed);
}

std::vector<std::uint8_t> compute_tag(const Key256& key,
                                      std::span<const std::uint8_t> context,
                                      std::span<const std::uint8_t> message,
                                      TagSize tag_size) {
    const auto full = compute_full_output(key, context, message, tag_size);
    const auto bytes = tag_size_bytes(tag_size);
    return std::vector<std::uint8_t>(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(bytes));
}

bool verify_tag(const Key256& key,
                std::span<const std::uint8_t> context,
                std::span<const std::uint8_t> message,
                std::span<const std::uint8_t> supplied_tag) {
    if (!is_supported_tag_size(supplied_tag.size())) return false;
    const auto size = checked_tag_size(supplied_tag.size());
    const auto expected = compute_full_output(key, context, message, size);
    std::uint8_t aggregate = 0U;
    for (std::size_t i = 0; i < supplied_tag.size(); ++i) {
        aggregate |= static_cast<std::uint8_t>(expected[i] ^ supplied_tag[i]);
    }
    return aggregate == 0U;
}

} // namespace pvcmac0_independent
