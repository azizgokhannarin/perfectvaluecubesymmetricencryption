#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace pvcaead0 {

typedef std::array<std::uint8_t, 32> Key256;
typedef std::array<std::uint8_t, 24> Nonce192;
typedef std::array<std::uint8_t, 32> StreamBlock256;

struct KeyPair512 {
    Key256 encryption_key;
    Key256 authentication_key;
};

enum class TagSize : std::uint8_t {
    Bits128 = 16,
    Bits192 = 24,
    Bits256 = 32,
};

struct SealedMessage {
    std::vector<std::uint8_t> ciphertext;
    std::vector<std::uint8_t> tag;
};

inline std::size_t tag_size_bytes(TagSize size) noexcept {
    return static_cast<std::size_t>(size);
}

bool is_supported_tag_size(std::size_t bytes) noexcept;
TagSize tag_size_from_bytes(std::size_t bytes);

std::vector<std::uint8_t> frame_stream_block(
    const Nonce192& nonce,
    std::uint64_t counter,
    TagSize tag_size);

std::vector<std::uint8_t> frame_authentication_context(
    const Nonce192& nonce,
    std::span<const std::uint8_t> associated_data,
    TagSize tag_size);

SealedMessage seal(
    const KeyPair512& keys,
    const Nonce192& nonce,
    std::span<const std::uint8_t> associated_data,
    std::span<const std::uint8_t> plaintext,
    TagSize tag_size);

std::optional<std::vector<std::uint8_t>> open(
    const KeyPair512& keys,
    const Nonce192& nonce,
    std::span<const std::uint8_t> associated_data,
    std::span<const std::uint8_t> ciphertext,
    std::span<const std::uint8_t> supplied_tag);

} // namespace pvcaead0
