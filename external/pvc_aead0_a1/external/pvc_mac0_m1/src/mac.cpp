#include "pvcmac0/mac.hpp"

#include "pvc1/key_schedule.hpp"

#include <array>
#include <limits>
#include <stdexcept>
#include <string>

namespace pvcmac0 {
namespace {

constexpr std::array<std::uint8_t, 9> kMagic{
    0x50U, 0x56U, 0x43U, 0x2DU, 0x4DU, 0x41U, 0x43U, 0x2DU, 0x30U,
}; // "PVC-MAC-0"
constexpr std::uint8_t kSeparator = 0x00U;
constexpr std::uint8_t kFrameVersion = 0x01U;
constexpr std::uint8_t kPrimitiveProfileC1 = 0xC1U;
constexpr std::uint8_t kReserved = 0x00U;
constexpr std::size_t kHeaderSize = 30U;

void append_u64_be(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (unsigned shift = 56U;; shift -= 8U) {
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFU));
        if (shift == 0U) break;
    }
}

std::uint64_t checked_u64_length(std::size_t size, const char* field) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (size > static_cast<std::size_t>(std::numeric_limits<std::uint64_t>::max())) {
            throw std::length_error(std::string(field) + " exceeds the u64 framing limit");
        }
    }
    return static_cast<std::uint64_t>(size);
}

} // namespace

bool is_supported_tag_size(std::size_t bytes) noexcept {
    return bytes == tag_size_bytes(TagSize::Bits128)
        || bytes == tag_size_bytes(TagSize::Bits192)
        || bytes == tag_size_bytes(TagSize::Bits256);
}

TagSize tag_size_from_bytes(std::size_t bytes) {
    switch (bytes) {
        case 16U: return TagSize::Bits128;
        case 24U: return TagSize::Bits192;
        case 32U: return TagSize::Bits256;
        default: throw std::invalid_argument("PVC-MAC-0 tag size must be 16, 24, or 32 bytes");
    }
}

std::vector<std::uint8_t> frame_message(std::span<const std::uint8_t> context,
                                        std::span<const std::uint8_t> message,
                                        TagSize tag_size) {
    const auto tag_bytes = tag_size_bytes(tag_size);
    if (!is_supported_tag_size(tag_bytes)) {
        throw std::invalid_argument("unsupported PVC-MAC-0 tag size");
    }

    if (context.size() > std::numeric_limits<std::size_t>::max() - kHeaderSize
        || message.size() > std::numeric_limits<std::size_t>::max() - kHeaderSize - context.size()) {
        throw std::length_error("PVC-MAC-0 frame size overflows size_t");
    }

    std::vector<std::uint8_t> framed;
    framed.reserve(kHeaderSize + context.size() + message.size());
    framed.insert(framed.end(), kMagic.begin(), kMagic.end());
    framed.push_back(kSeparator);
    framed.push_back(kFrameVersion);
    framed.push_back(kPrimitiveProfileC1);
    framed.push_back(static_cast<std::uint8_t>(tag_bytes));
    framed.push_back(kReserved);
    append_u64_be(framed, checked_u64_length(context.size(), "context"));
    append_u64_be(framed, checked_u64_length(message.size(), "message"));
    framed.insert(framed.end(), context.begin(), context.end());
    framed.insert(framed.end(), message.begin(), message.end());
    return framed;
}

FullTag256 compute_full_tag_internal(const Key256& key,
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
    const auto full = compute_full_tag_internal(key, context, message, tag_size);
    const auto length = tag_size_bytes(tag_size);
    return {full.begin(), full.begin() + static_cast<std::ptrdiff_t>(length)};
}

bool verify_tag(const Key256& key,
                std::span<const std::uint8_t> context,
                std::span<const std::uint8_t> message,
                std::span<const std::uint8_t> supplied_tag) {
    if (!is_supported_tag_size(supplied_tag.size())) return false;

    const auto tag_size = tag_size_from_bytes(supplied_tag.size());
    const auto expected = compute_full_tag_internal(key, context, message, tag_size);
    std::uint8_t difference = 0U;
    for (std::size_t i = 0; i < supplied_tag.size(); ++i) {
        difference = static_cast<std::uint8_t>(difference | (expected[i] ^ supplied_tag[i]));
    }
    return difference == 0U;
}

} // namespace pvcmac0
