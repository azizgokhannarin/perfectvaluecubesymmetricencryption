#include "pvcmac0/mac.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <iostream>
#include <vector>

namespace {

std::size_t bit_distance(std::span<const std::uint8_t> a, std::span<const std::uint8_t> b) {
    std::size_t distance = 0U;
    for (std::size_t i = 0; i < a.size(); ++i) {
        distance += static_cast<std::size_t>(std::popcount(static_cast<unsigned>(a[i] ^ b[i])));
    }
    return distance;
}

} // namespace

int main() {
    pvcmac0::Key256 key{};
    std::vector<std::uint8_t> context{'P','V','C','-','M','A','C','-','0'};
    std::vector<std::uint8_t> message(32U, 0U);
    const auto baseline = pvcmac0::compute_tag(key, context, message, pvcmac0::TagSize::Bits256);

    std::size_t total = 0U;
    std::size_t minimum = 256U;
    std::size_t maximum = 0U;
    std::size_t samples = 0U;
    for (std::size_t bit = 0; bit < message.size() * 8U; ++bit) {
        auto changed = message;
        changed[bit / 8U] ^= static_cast<std::uint8_t>(1U << (bit % 8U));
        const auto tag = pvcmac0::compute_tag(key, context, changed, pvcmac0::TagSize::Bits256);
        const auto distance = bit_distance(baseline, tag);
        total += distance;
        minimum = std::min(minimum, distance);
        maximum = std::max(maximum, distance);
        ++samples;
    }
    std::cout << "PVC-MAC-0 v0.1.0 message-bit avalanche baseline\n"
              << "samples=" << samples << '\n'
              << "average=" << static_cast<double>(total) / static_cast<double>(samples) << '\n'
              << "minimum=" << minimum << '\n'
              << "maximum=" << maximum << '\n';
    return 0;
}
