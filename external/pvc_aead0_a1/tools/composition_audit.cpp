#include "pvcaead0/aead.hpp"

#include <cstdint>
#include <iostream>
#include <vector>

namespace {

std::uint64_t next(std::uint64_t& state) {
    state ^= state << 13U;
    state ^= state >> 7U;
    state ^= state << 17U;
    return state;
}

std::uint8_t byte(std::uint64_t& state) {
    return static_cast<std::uint8_t>(next(state) >> 56U);
}

pvcaead0::TagSize tag_for(std::size_t index) {
    switch (index % 3U) {
        case 0U: return pvcaead0::TagSize::Bits128;
        case 1U: return pvcaead0::TagSize::Bits192;
        default: return pvcaead0::TagSize::Bits256;
    }
}

} // namespace

int main() {
    std::uint64_t state = 0x4145414441554449ULL;
    std::size_t valid_roundtrips = 0U;
    std::size_t rejected_tampers = 0U;

    for (std::size_t case_index = 0U; case_index < 128U; ++case_index) {
        pvcaead0::KeyPair512 keys{};
        pvcaead0::Nonce192 nonce{};
        for (auto& value : keys.encryption_key) value = byte(state);
        for (auto& value : keys.authentication_key) value = byte(state);
        for (auto& value : nonce) value = byte(state);
        std::vector<std::uint8_t> ad(case_index % 29U);
        std::vector<std::uint8_t> plaintext((case_index * 17U) % 97U);
        for (auto& value : ad) value = byte(state);
        for (auto& value : plaintext) value = byte(state);

        const auto tag_size = tag_for(case_index);
        const auto sealed = pvcaead0::seal(keys, nonce, ad, plaintext, tag_size);
        const auto opened = pvcaead0::open(keys, nonce, ad, sealed.ciphertext, sealed.tag);
        if (!opened.has_value() || *opened != plaintext) {
            std::cerr << "roundtrip failure at case " << case_index << '\n';
            return 1;
        }
        ++valid_roundtrips;

        auto wrong_nonce = nonce;
        wrong_nonce[case_index % wrong_nonce.size()] ^= 0x01U;
        if (pvcaead0::open(keys, wrong_nonce, ad, sealed.ciphertext, sealed.tag).has_value()) return 1;
        ++rejected_tampers;

        auto wrong_ad = ad;
        if (wrong_ad.empty()) wrong_ad.push_back(0U);
        else wrong_ad[case_index % wrong_ad.size()] ^= 0x01U;
        if (pvcaead0::open(keys, nonce, wrong_ad, sealed.ciphertext, sealed.tag).has_value()) return 1;
        ++rejected_tampers;

        if (!sealed.ciphertext.empty()) {
            auto wrong_ciphertext = sealed.ciphertext;
            wrong_ciphertext[case_index % wrong_ciphertext.size()] ^= 0x01U;
            if (pvcaead0::open(keys, nonce, ad, wrong_ciphertext, sealed.tag).has_value()) return 1;
            ++rejected_tampers;
        }

        auto wrong_tag = sealed.tag;
        wrong_tag[case_index % wrong_tag.size()] ^= 0x01U;
        if (pvcaead0::open(keys, nonce, ad, sealed.ciphertext, wrong_tag).has_value()) return 1;
        ++rejected_tampers;
    }

    std::cout << "cases=128\n"
              << "valid_roundtrips=" << valid_roundtrips << '\n'
              << "rejected_tampers=" << rejected_tampers << '\n'
              << "unexpected_acceptances=0\n";
    return 0;
}
