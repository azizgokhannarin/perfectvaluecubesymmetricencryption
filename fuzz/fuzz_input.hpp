#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <span>

namespace pvcrotsymenc1::fuzzing {

class InputReader {
public:
    explicit InputReader(std::span<const std::uint8_t> input) noexcept
        : input_(input) {}

    [[nodiscard]] std::uint8_t take_byte() noexcept {
        if (offset_ == input_.size()) return 0U;
        return input_[offset_++];
    }

    [[nodiscard]] std::uint16_t take_u16_be() noexcept {
        const auto high = static_cast<std::uint16_t>(take_byte());
        const auto low = static_cast<std::uint16_t>(take_byte());
        return static_cast<std::uint16_t>(static_cast<std::uint16_t>(high << 8U) | low);
    }

    template <std::size_t Size>
    [[nodiscard]] std::array<std::uint8_t, Size> take_array() noexcept {
        std::array<std::uint8_t, Size> output{};
        for (auto& byte : output) byte = take_byte();
        return output;
    }

    [[nodiscard]] std::span<const std::uint8_t> remaining() const noexcept {
        return input_.subspan(offset_);
    }

private:
    std::span<const std::uint8_t> input_;
    std::size_t offset_ = 0U;
};

[[nodiscard]] inline std::size_t split_index(std::uint16_t hint,
                                             std::size_t size) noexcept {
    if (size == std::numeric_limits<std::size_t>::max()) {
        return static_cast<std::size_t>(hint);
    }
    return static_cast<std::size_t>(hint) % (size + 1U);
}

[[noreturn]] inline void differential_failure(const char* message) noexcept {
    std::fputs(message, stderr);
    std::fputc('\n', stderr);
    std::abort();
}

inline void require(bool condition, const char* message) noexcept {
    if (!condition) differential_failure(message);
}

} // namespace pvcrotsymenc1::fuzzing
