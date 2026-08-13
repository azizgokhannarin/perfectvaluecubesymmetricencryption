#include "pvcaead0/aead.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <string>
#include <unordered_set>
#include <vector>

namespace {

std::string key(const std::vector<std::uint8_t>& value) {
    return {reinterpret_cast<const char*>(value.data()), value.size()};
}

pvcaead0::TagSize tag_for(std::size_t index) {
    switch (index) {
        case 0U: return pvcaead0::TagSize::Bits128;
        case 1U: return pvcaead0::TagSize::Bits192;
        default: return pvcaead0::TagSize::Bits256;
    }
}

} // namespace

int main() {
    std::unordered_set<std::string> frames;
    std::size_t stream_count = 0U;
    std::size_t auth_count = 0U;

    for (std::size_t t = 0; t < 3U; ++t) {
        for (std::size_t n = 0; n < 64U; ++n) {
            pvcaead0::Nonce192 nonce{};
            for (std::size_t i = 0; i < nonce.size(); ++i) {
                nonce[i] = static_cast<std::uint8_t>((n * 37U + i * 19U) & 0xffU);
            }
            for (std::uint64_t counter = 0U; counter < 128U; ++counter) {
                const auto frame = pvcaead0::frame_stream_block(nonce, counter, tag_for(t));
                if (!frames.insert(key(frame)).second) {
                    std::cerr << "stream collision\n";
                    return 1;
                }
                ++stream_count;
            }
            for (std::size_t length = 0U; length < 32U; ++length) {
                std::vector<std::uint8_t> ad(length);
                for (std::size_t i = 0; i < ad.size(); ++i) {
                    ad[i] = static_cast<std::uint8_t>((n * 11U + length * 7U + i * 23U) & 0xffU);
                }
                const auto frame = pvcaead0::frame_authentication_context(nonce, ad, tag_for(t));
                if (!frames.insert(key(frame)).second) {
                    std::cerr << "authentication collision\n";
                    return 1;
                }
                ++auth_count;
            }
        }
    }

    std::cout << "stream_frames=" << stream_count << '\n'
              << "authentication_frames=" << auth_count << '\n'
              << "total_frames=" << frames.size() << '\n'
              << "collisions=0\n";
    return 0;
}
