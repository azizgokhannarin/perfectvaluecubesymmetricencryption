#include "pvc1/cube.hpp"

#include <algorithm>
#include <iomanip>
#include <ostream>
#include <stdexcept>

namespace pvc1 {
namespace {

constexpr Cube::Storage kPerfectCube = {
    68,69,182,183,184,185,74,75,
    84,85,169,168,167,166,90,91,
    107,154,102,152,151,105,149,100,
    123,138,137,119,120,134,133,116,
    139,122,121,135,136,118,117,132,
    155,106,150,104,103,153,101,148,
    164,165,89,88,87,86,170,171,
    180,181,70,71,72,73,186,187,

    64,65,178,179,188,189,78,79,
    80,81,173,172,163,162,94,95,
    111,158,98,156,147,109,145,96,
    127,142,141,115,124,130,129,112,
    143,126,125,131,140,114,113,128,
    159,110,146,108,99,157,97,144,
    160,161,93,92,83,82,174,175,
    176,177,66,67,76,77,190,191,

    4,5,246,247,248,249,10,11,
    20,21,233,232,231,230,26,27,
    43,218,38,216,215,41,213,36,
    59,202,201,55,56,198,197,52,
    203,58,57,199,200,54,53,196,
    219,42,214,40,39,217,37,212,
    228,229,25,24,23,22,234,235,
    244,245,6,7,8,9,250,251,

    0,1,242,243,252,253,14,15,
    16,17,237,236,227,226,30,31,
    47,222,34,220,211,45,209,32,
    63,206,205,51,60,194,193,48,
    207,62,61,195,204,50,49,192,
    223,46,210,44,35,221,33,208,
    224,225,29,28,19,18,238,239,
    240,241,2,3,12,13,254,255,

    255,254,13,12,3,2,241,240,
    239,238,18,19,28,29,225,224,
    208,33,221,35,44,210,46,223,
    192,49,50,204,195,61,62,207,
    48,193,194,60,51,205,206,63,
    32,209,45,211,220,34,222,47,
    31,30,226,227,236,237,17,16,
    15,14,253,252,243,242,1,0,

    251,250,9,8,7,6,245,244,
    235,234,22,23,24,25,229,228,
    212,37,217,39,40,214,42,219,
    196,53,54,200,199,57,58,203,
    52,197,198,56,55,201,202,59,
    36,213,41,215,216,38,218,43,
    27,26,230,231,232,233,21,20,
    11,10,249,248,247,246,5,4,

    191,190,77,76,67,66,177,176,
    175,174,82,83,92,93,161,160,
    144,97,157,99,108,146,110,159,
    128,113,114,140,131,125,126,143,
    112,129,130,124,115,141,142,127,
    96,145,109,147,156,98,158,111,
    95,94,162,163,172,173,81,80,
    79,78,189,188,179,178,65,64,

    187,186,73,72,71,70,181,180,
    171,170,86,87,88,89,165,164,
    148,101,153,103,104,150,106,155,
    132,117,118,136,135,121,122,139,
    116,133,134,120,119,137,138,123,
    100,149,105,151,152,102,154,107,
    91,90,166,167,168,169,85,84,
    75,74,185,184,183,182,69,68
};

constexpr std::uint8_t normalize_amount(std::uint8_t amount) {
    return static_cast<std::uint8_t>(amount % kCubeSide);
}

constexpr Cube::DigestCells make_body_diagonals(const Cube::Storage& cells) {
    Cube::DigestCells result{};
    std::size_t out = 0;
    for (std::uint8_t i = 0; i < kCubeSide; ++i) {
        result[out++] = cells[Cube::index({i, i, i})];
    }
    for (std::uint8_t i = 0; i < kCubeSide; ++i) {
        result[out++] = cells[Cube::index({static_cast<std::uint8_t>(7U - i), i, i})];
    }
    for (std::uint8_t i = 0; i < kCubeSide; ++i) {
        result[out++] = cells[Cube::index({i, static_cast<std::uint8_t>(7U - i), i})];
    }
    for (std::uint8_t i = 0; i < kCubeSide; ++i) {
        result[out++] = cells[Cube::index({i, i, static_cast<std::uint8_t>(7U - i)})];
    }
    return result;
}

constexpr auto kPerfectBodyDiagonals = make_body_diagonals(kPerfectCube);

} // namespace

Cube::Cube(Storage cells) : cells_(std::move(cells)) {}

Cube Cube::perfect() {
    return Cube{kPerfectCube};
}

const Cube::DigestCells& Cube::perfect_body_diagonals() noexcept {
    return kPerfectBodyDiagonals;
}

std::uint8_t Cube::at(Coord coord) const {
    if (coord.x >= kCubeSide || coord.y >= kCubeSide || coord.z >= kCubeSide) {
        throw std::out_of_range("Cube coordinate is outside [0,7]");
    }
    return cells_[index(coord)];
}

std::uint8_t& Cube::at(Coord coord) {
    if (coord.x >= kCubeSide || coord.y >= kCubeSide || coord.z >= kCubeSide) {
        throw std::out_of_range("Cube coordinate is outside [0,7]");
    }
    return cells_[index(coord)];
}

void Cube::rotate_line(Axis axis, Coord line_point, std::uint8_t amount) {
    if (line_point.x >= kCubeSide || line_point.y >= kCubeSide || line_point.z >= kCubeSide) {
        throw std::out_of_range("Cube coordinate is outside [0,7]");
    }
    const auto shift = normalize_amount(amount);
    if (shift == 0U) {
        return;
    }

    std::array<std::uint8_t, kCubeSide> old{};
    for (std::uint8_t i = 0; i < kCubeSide; ++i) {
        auto coord = line_point;
        switch (axis) {
        case Axis::X: coord.x = i; break;
        case Axis::Y: coord.y = i; break;
        case Axis::Z: coord.z = i; break;
        }
        old[i] = unchecked(coord);
    }

    for (std::uint8_t i = 0; i < kCubeSide; ++i) {
        auto coord = line_point;
        const auto destination =
            static_cast<std::uint8_t>((static_cast<unsigned>(i) + shift) % kCubeSide);
        switch (axis) {
        case Axis::X: coord.x = destination; break;
        case Axis::Y: coord.y = destination; break;
        case Axis::Z: coord.z = destination; break;
        }
        unchecked(coord) = old[i];
    }
}

std::array<std::uint32_t, 192> Cube::line_sums() const {
    std::array<std::uint32_t, 192> sums{};
    std::size_t out = 0;

    for (std::uint8_t z = 0; z < kCubeSide; ++z) {
        for (std::uint8_t y = 0; y < kCubeSide; ++y) {
            std::uint32_t sum = 0;
            for (std::uint8_t x = 0; x < kCubeSide; ++x) {
                sum += unchecked({x, y, z});
            }
            sums[out++] = sum;
        }
    }

    for (std::uint8_t z = 0; z < kCubeSide; ++z) {
        for (std::uint8_t x = 0; x < kCubeSide; ++x) {
            std::uint32_t sum = 0;
            for (std::uint8_t y = 0; y < kCubeSide; ++y) {
                sum += unchecked({x, y, z});
            }
            sums[out++] = sum;
        }
    }

    for (std::uint8_t y = 0; y < kCubeSide; ++y) {
        for (std::uint8_t x = 0; x < kCubeSide; ++x) {
            std::uint32_t sum = 0;
            for (std::uint8_t z = 0; z < kCubeSide; ++z) {
                sum += unchecked({x, y, z});
            }
            sums[out++] = sum;
        }
    }

    return sums;
}

bool Cube::is_balanced() const {
    const auto sums = line_sums();
    return std::all_of(sums.begin(), sums.end(),
                       [](std::uint32_t value) { return value == kBalancedLineSum; });
}

std::array<std::uint16_t, 256> Cube::histogram() const {
    std::array<std::uint16_t, 256> counts{};
    for (const auto value : cells_) {
        ++counts[value];
    }
    return counts;
}

bool Cube::has_double_byte_histogram() const {
    const auto counts = histogram();
    return std::all_of(counts.begin(), counts.end(),
                       [](std::uint16_t count) { return count == 2U; });
}

Cube::DigestCells Cube::body_diagonals() const {
    DigestCells result{};
    std::size_t out = 0;

    for (std::uint8_t i = 0; i < kCubeSide; ++i) {
        result[out++] = unchecked({i, i, i});
    }
    for (std::uint8_t i = 0; i < kCubeSide; ++i) {
        result[out++] = unchecked({static_cast<std::uint8_t>(7U - i), i, i});
    }
    for (std::uint8_t i = 0; i < kCubeSide; ++i) {
        result[out++] = unchecked({i, static_cast<std::uint8_t>(7U - i), i});
    }
    for (std::uint8_t i = 0; i < kCubeSide; ++i) {
        result[out++] = unchecked({i, i, static_cast<std::uint8_t>(7U - i)});
    }

    return result;
}

void Cube::print_layers(std::ostream& out) const {
    for (std::uint8_t z = 0; z < kCubeSide; ++z) {
        out << "z=" << static_cast<unsigned>(z) << '\n';
        for (std::uint8_t y = 0; y < kCubeSide; ++y) {
            for (std::uint8_t x = 0; x < kCubeSide; ++x) {
                out << std::setw(3) << static_cast<unsigned>(unchecked({x, y, z}));
                if (x + 1U != kCubeSide) {
                    out << ' ';
                }
            }
            out << '\n';
        }
        if (z + 1U != kCubeSide) {
            out << '\n';
        }
    }
}

Coord advance(Coord coord, Axis axis, std::uint8_t amount) {
    const auto shift = static_cast<std::uint8_t>(amount % kCubeSide);
    switch (axis) {
    case Axis::X:
        coord.x = static_cast<std::uint8_t>((coord.x + shift) % kCubeSide);
        break;
    case Axis::Y:
        coord.y = static_cast<std::uint8_t>((coord.y + shift) % kCubeSide);
        break;
    case Axis::Z:
        coord.z = static_cast<std::uint8_t>((coord.z + shift) % kCubeSide);
        break;
    }
    return coord;
}

bool line_contains(Axis axis, Coord line_point, Coord point) {
    switch (axis) {
    case Axis::X:
        return line_point.y == point.y && line_point.z == point.z;
    case Axis::Y:
        return line_point.x == point.x && line_point.z == point.z;
    case Axis::Z:
        return line_point.x == point.x && line_point.y == point.y;
    }
    return false;
}

const char* axis_name(Axis axis) {
    switch (axis) {
    case Axis::X: return "X";
    case Axis::Y: return "Y";
    case Axis::Z: return "Z";
    }
    return "?";
}

} // namespace pvc1
