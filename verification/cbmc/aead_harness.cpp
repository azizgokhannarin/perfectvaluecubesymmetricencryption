#include "pvcaead0/aead.hpp"

#include "pvc1/key_schedule.hpp"
#include "pvcmac0/mac.hpp"

extern "C" unsigned char nondet_uchar();
extern "C" unsigned long nondet_ulong();
extern "C" bool nondet_bool();
extern "C" void __CPROVER_assume(bool condition);
extern "C" void __CPROVER_assert(bool condition, const char* description);

namespace cbmc_harness {

constexpr std::size_t kMaximumPayload = 33U;
constexpr std::size_t kMaximumAssociatedData = 8U;
constexpr std::size_t kMaximumFrameAssociatedData = 16U;

bool g_inside_open = false;
bool g_verify_called = false;
bool g_verify_result = false;
std::size_t g_prf_calls = 0U;

bool supported_tag_length(std::size_t size) {
    return size == 16U || size == 24U || size == 32U;
}

std::size_t expected_blocks(std::size_t size) {
    return size == 0U ? 0U : 1U + ((size - 1U) / 32U);
}

pvcaead0::TagSize nondet_tag_size() {
    const auto selector = nondet_uchar();
    __CPROVER_assume(selector < 3U);
    if (selector == 0U) return pvcaead0::TagSize::Bits128;
    if (selector == 1U) return pvcaead0::TagSize::Bits192;
    return pvcaead0::TagSize::Bits256;
}

void reset_stubs(bool inside_open) {
    g_inside_open = inside_open;
    g_verify_called = false;
    g_verify_result = false;
    g_prf_calls = 0U;
}

} // namespace cbmc_harness

using namespace cbmc_harness;

namespace pvc1 {

ResearchOutput research_keyed_return_output_a2(
    const ResearchKey256&,
    const std::vector<std::uint8_t>& message) {
    __CPROVER_assert(message.size() == 48U,
                     "each C1 stream input is one complete StreamFrame");
    if (g_inside_open) {
        __CPROVER_assert(g_verify_called,
                         "open authenticates before the first decrypt block");
        __CPROVER_assert(g_verify_result,
                         "open only decrypts after successful verification");
    }
    ++g_prf_calls;

    ResearchOutput arbitrary_output;
    return arbitrary_output;
}

} // namespace pvc1

namespace pvcmac0 {

std::vector<std::uint8_t> compute_tag(
    const Key256&,
    const std::vector<std::uint8_t>&,
    const std::vector<std::uint8_t>&,
    TagSize tag_size) {
    const auto size = static_cast<std::size_t>(tag_size);
    __CPROVER_assert(supported_tag_length(size),
                     "seal passes only a supported tag profile to M1");
    return std::vector<std::uint8_t>(size);
}

bool verify_tag(
    const Key256&,
    const std::vector<std::uint8_t>&,
    std::span<const std::uint8_t>,
    std::span<const std::uint8_t> supplied_tag) {
    __CPROVER_assert(!g_verify_called, "open calls M1 verification once");
    __CPROVER_assert(supported_tag_length(supplied_tag.size()),
                     "only a supported tag length reaches M1 verification");
    g_verify_called = true;
    g_verify_result = nondet_bool();
    return g_verify_result;
}

} // namespace pvcmac0

void verify_frames() {
    pvcaead0::Nonce192 nonce;
    for (std::size_t index = 0U; index < 24U; ++index) {
        nonce[index] = nondet_uchar();
    }
    const std::uint64_t counter = nondet_ulong();
    const pvcaead0::TagSize tag_size = nondet_tag_size();
    const auto tag_bytes = static_cast<std::size_t>(tag_size);

    const std::vector<std::uint8_t> stream =
        pvcaead0::frame_stream_block(nonce, counter, tag_size);
    __CPROVER_assert(stream.size() == 48U, "StreamFrame has exactly 48 bytes");
    __CPROVER_assert(stream[14U] == tag_bytes, "StreamFrame binds the tag profile");
    for (std::size_t index = 0U; index < 24U; ++index) {
        __CPROVER_assert(stream[16U + index] == nonce[index],
                         "StreamFrame preserves every nonce byte");
    }
    for (std::size_t index = 0U; index < 8U; ++index) {
        const unsigned shift = static_cast<unsigned>((7U - index) * 8U);
        const auto expected = static_cast<std::uint8_t>((counter >> shift) & 0xFFU);
        __CPROVER_assert(stream[40U + index] == expected,
                         "StreamFrame encodes the counter in big-endian order");
    }

    std::uint8_t associated_data[kMaximumFrameAssociatedData];
    const auto associated_data_size = nondet_ulong();
    __CPROVER_assume(associated_data_size <= kMaximumFrameAssociatedData);
    const std::vector<std::uint8_t> auth = pvcaead0::frame_authentication_context(
        nonce,
        std::span<const std::uint8_t>(associated_data, associated_data_size),
        tag_size);
    __CPROVER_assert(auth.size() == 49U + associated_data_size,
                     "AuthContext size equals its fixed prefix plus AD length");
    __CPROVER_assert(auth[15U] == tag_bytes, "AuthContext binds the tag profile");
    for (std::size_t index = 0U; index < associated_data_size; ++index) {
        __CPROVER_assert(auth[49U + index] == associated_data[index],
                         "AuthContext preserves every associated-data byte");
    }
}

void verify_seal_lengths() {
    pvcaead0::KeyPair512 keys;
    pvcaead0::Nonce192 nonce;
    std::uint8_t associated_data[kMaximumAssociatedData];
    std::uint8_t plaintext[kMaximumPayload];
    const auto associated_data_size = nondet_ulong();
    const auto plaintext_size = nondet_ulong();
    __CPROVER_assume(associated_data_size <= kMaximumAssociatedData);
    __CPROVER_assume(plaintext_size <= kMaximumPayload);
    const pvcaead0::TagSize tag_size = nondet_tag_size();

    reset_stubs(false);
    const pvcaead0::SealedMessage sealed = pvcaead0::seal(
        keys,
        nonce,
        std::span<const std::uint8_t>(associated_data, associated_data_size),
        std::span<const std::uint8_t>(plaintext, plaintext_size),
        tag_size);

    __CPROVER_assert(sealed.ciphertext.size() == plaintext_size,
                     "seal preserves the plaintext length");
    __CPROVER_assert(sealed.tag.size() == static_cast<std::size_t>(tag_size),
                     "seal returns the selected tag length");
    __CPROVER_assert(g_prf_calls == expected_blocks(plaintext_size),
                     "seal derives exactly one stream block per payload block");
}

void verify_open_control_flow() {
    pvcaead0::KeyPair512 keys;
    pvcaead0::Nonce192 nonce;
    std::uint8_t associated_data[kMaximumAssociatedData];
    std::uint8_t ciphertext[kMaximumPayload];
    std::uint8_t tag[32U];
    const auto associated_data_size = nondet_ulong();
    const auto ciphertext_size = nondet_ulong();
    const auto tag_size = nondet_ulong();
    __CPROVER_assume(associated_data_size <= kMaximumAssociatedData);
    __CPROVER_assume(ciphertext_size <= kMaximumPayload);

    reset_stubs(true);
    std::optional<std::vector<std::uint8_t>> opened = pvcaead0::open(
        keys,
        nonce,
        std::span<const std::uint8_t>(associated_data, associated_data_size),
        std::span<const std::uint8_t>(ciphertext, ciphertext_size),
        std::span<const std::uint8_t>(tag, tag_size));

    if (!supported_tag_length(tag_size)) {
        __CPROVER_assert(!g_verify_called,
                         "an invalid tag length cannot enter verification");
        __CPROVER_assert(g_prf_calls == 0U,
                         "an invalid tag length cannot enter decryption");
        __CPROVER_assert(!opened.has_value(),
                         "an invalid tag length cannot return plaintext");
    } else if (!g_verify_result) {
        __CPROVER_assert(g_verify_called, "a valid tag length is verified");
        __CPROVER_assert(g_prf_calls == 0U,
                         "a failed verification cannot enter decryption");
        __CPROVER_assert(!opened.has_value(),
                         "a failed verification cannot return plaintext");
    } else {
        __CPROVER_assert(g_verify_called, "successful open performed verification");
        __CPROVER_assert(opened.has_value(), "successful verification returns plaintext");
        __CPROVER_assert((*opened).size() == ciphertext_size,
                         "open success preserves the ciphertext length");
        __CPROVER_assert(g_prf_calls == expected_blocks(ciphertext_size),
                         "open derives exactly one stream block per payload block");
    }
}
