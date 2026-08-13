#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace pvcaead0 {

// PVC-AEAD-0 Candidate A1 / v0.2.0 is experimental research software. It is not production
// cryptography and carries no proven security or post-quantum claim.
using Key256 = std::array<std::uint8_t, 32>;
using Nonce192 = std::array<std::uint8_t, 24>;
using StreamBlock256 = std::array<std::uint8_t, 32>;

struct KeyPair512 {
    Key256 encryption_key{};
    Key256 authentication_key{};
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

[[nodiscard]] constexpr std::size_t tag_size_bytes(TagSize size) noexcept {
    return static_cast<std::size_t>(size);
}

[[nodiscard]] bool is_supported_tag_size(std::size_t bytes) noexcept;
[[nodiscard]] TagSize tag_size_from_bytes(std::size_t bytes);

// Canonical C1 input for one keystream block. Exposed for audit and future
// independent implementations.
[[nodiscard]] std::vector<std::uint8_t> frame_stream_block(
    const Nonce192& nonce,
    std::uint64_t counter,
    TagSize tag_size);

// Canonical PVC-MAC-0 context. Ciphertext is passed separately as the MAC
// message, so the frozen M1 frame binds its length injectively.
[[nodiscard]] std::vector<std::uint8_t> frame_authentication_context(
    const Nonce192& nonce,
    std::span<const std::uint8_t> associated_data,
    TagSize tag_size);

[[nodiscard]] SealedMessage seal(
    const KeyPair512& keys,
    const Nonce192& nonce,
    std::span<const std::uint8_t> associated_data,
    std::span<const std::uint8_t> plaintext,
    TagSize tag_size = TagSize::Bits256);

// Verifies the ciphertext tag before deriving or returning plaintext.
// Invalid tag lengths and invalid tags return std::nullopt.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> open(
    const KeyPair512& keys,
    const Nonce192& nonce,
    std::span<const std::uint8_t> associated_data,
    std::span<const std::uint8_t> ciphertext,
    std::span<const std::uint8_t> supplied_tag);

} // namespace pvcaead0
