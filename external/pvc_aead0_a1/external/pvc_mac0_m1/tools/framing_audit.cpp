#include "pvcmac0/mac.hpp"

#include <cstdint>
#include <iostream>
#include <set>
#include <string>
#include <stdexcept>
#include <vector>

namespace {

std::vector<std::uint8_t> base256(std::size_t value, std::size_t length) {
    std::vector<std::uint8_t> out(length);
    for (std::size_t i = 0; i < length; ++i) {
        out[length - 1U - i] = static_cast<std::uint8_t>(value & 0xFFU);
        value >>= 8U;
    }
    return out;
}

} // namespace

int main() {
    try {
        std::set<std::string> seen;
        std::size_t tested = 0U;
        const std::array<pvcmac0::TagSize, 3> sizes{
            pvcmac0::TagSize::Bits128, pvcmac0::TagSize::Bits192, pvcmac0::TagSize::Bits256};
        for (const auto size : sizes) {
            for (std::size_t context_length = 0; context_length <= 2U; ++context_length) {
                const std::size_t context_count = context_length == 0U ? 1U : 256U;
                for (std::size_t ci = 0; ci < context_count; ++ci) {
                    const auto context = base256(ci, context_length);
                    for (std::size_t message_length = 0; message_length <= 2U; ++message_length) {
                        const std::size_t message_count = message_length == 0U ? 1U : 256U;
                        for (std::size_t mi = 0; mi < message_count; ++mi) {
                            const auto message = base256(mi, message_length);
                            const auto frame = pvcmac0::frame_message(context, message, size);
                            const std::string key(reinterpret_cast<const char*>(frame.data()), frame.size());
                            if (!seen.insert(key).second) throw std::runtime_error("framing collision found");
                            ++tested;
                        }
                    }
                }
            }
        }
        std::cout << "PVC-MAC-0 framing audit\n"
                  << "frames_tested=" << tested << '\n'
                  << "collisions=0\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
