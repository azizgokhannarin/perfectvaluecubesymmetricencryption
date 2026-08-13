#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <iosfwd>

namespace pvc1 {

inline constexpr std::size_t kCubeSide = 8;
inline constexpr std::size_t kCubeCells = kCubeSide * kCubeSide * kCubeSide;
inline constexpr std::uint32_t kBalancedLineSum = 1020;

enum class Axis : std::uint8_t {
    X = 0,
    Y = 1,
    Z = 2,
};

struct Coord {
    std::uint8_t x{};
    std::uint8_t y{};
    std::uint8_t z{};

    friend constexpr bool operator==(const Coord&, const Coord&) = default;
};

class Cube {
public:
    using Storage = std::array<std::uint8_t, kCubeCells>;
    using DigestCells = std::array<std::uint8_t, 32>;

    Cube() = default;
    explicit Cube(Storage cells);

    [[nodiscard]] static Cube perfect();
    [[nodiscard]] static const DigestCells& perfect_body_diagonals() noexcept;

    [[nodiscard]] std::uint8_t at(Coord coord) const;
    [[nodiscard]] std::uint8_t& at(Coord coord);

    // Internal/research fast path. The caller must guarantee coordinates are in [0,7].
    [[nodiscard]] std::uint8_t unchecked(Coord coord) const noexcept {
        return cells_[index(coord)];
    }
    [[nodiscard]] std::uint8_t& unchecked(Coord coord) noexcept {
        return cells_[index(coord)];
    }

    // Positive rotation along the selected axis, modulo 8.
    // The line is the unique axis-parallel line passing through line_point.
    void rotate_line(Axis axis, Coord line_point, std::uint8_t amount);

    [[nodiscard]] bool is_balanced() const;
    [[nodiscard]] bool has_double_byte_histogram() const;
    [[nodiscard]] std::array<std::uint32_t, 192> line_sums() const;
    [[nodiscard]] std::array<std::uint16_t, 256> histogram() const;

    // Output order:
    // D0: (i, i, i)
    // D1: (7-i, i, i)
    // D2: (i, 7-i, i)
    // D3: (i, i, 7-i)
    // for i = 0..7, concatenated as D0 || D1 || D2 || D3.
    [[nodiscard]] DigestCells body_diagonals() const;

    [[nodiscard]] const Storage& storage() const noexcept { return cells_; }
    [[nodiscard]] bool operator==(const Cube&) const = default;

    void print_layers(std::ostream& out) const;

    [[nodiscard]] static constexpr std::size_t index(Coord coord) {
        return static_cast<std::size_t>(coord.z) * 64U
             + static_cast<std::size_t>(coord.y) * 8U
             + static_cast<std::size_t>(coord.x);
    }

private:
    Storage cells_{};
};

[[nodiscard]] Coord advance(Coord coord, Axis axis, std::uint8_t amount);
[[nodiscard]] bool line_contains(Axis axis, Coord line_point, Coord point);
[[nodiscard]] const char* axis_name(Axis axis);

} // namespace pvc1
