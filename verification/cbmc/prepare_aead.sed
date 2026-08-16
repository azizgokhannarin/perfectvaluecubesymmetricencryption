# CBMC 6.10.0 rejects anonymous C++ namespaces. Giving the one internal
# namespace a name preserves lookup and behavior while making the unchanged
# function bodies parseable by the verifier's C++11 frontend.
s/^namespace {$/namespace cbmc_internal {/
s/^} \/\/ namespace$/} \/\/ namespace cbmc_internal\
using namespace cbmc_internal;/
s/constexpr std::array<std::uint8_t, 10> kMagic{/constexpr std::array<std::uint8_t, 10> kMagic(/
s/0x30U,$/0x30U/
s/}; \/\/ "PVC-AEAD-0"/); \/\/ "PVC-AEAD-0"/
s/const auto framed = frame_stream_block/const std::vector<std::uint8_t> framed = frame_stream_block/
s/const auto stream = pvc1::research_keyed_return_output_a2/const pvc1::ResearchOutput stream = pvc1::research_keyed_return_output_a2/
s/const auto context = frame_authentication_context/const std::vector<std::uint8_t> context = frame_authentication_context/
s/const auto tag_size = tag_size_from_bytes/const TagSize tag_size = tag_size_from_bytes/
s/return std::nullopt;/return std::optional<std::vector<std::uint8_t>>();/
s/return apply_keystream(keys.encryption_key, nonce, ciphertext, tag_size);/return std::optional<std::vector<std::uint8_t>>(apply_keystream(keys.encryption_key, nonce, ciphertext, tag_size));/
s/throw std::length_error(std::string(field) + " exceeds the u64 framing limit");/throw std::length_error("u64 framing limit");/
s/std::numeric_limits<std::uint64_t>::max()/(~static_cast<std::uint64_t>(0))/g
s/std::numeric_limits<std::size_t>::max()/(~static_cast<std::size_t>(0))/g
