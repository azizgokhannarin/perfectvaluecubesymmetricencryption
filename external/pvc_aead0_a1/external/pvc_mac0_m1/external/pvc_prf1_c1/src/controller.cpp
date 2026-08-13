#include "pvc1/controller.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <stdexcept>

namespace pvc1 {
namespace {

constexpr std::uint8_t rotl8(std::uint8_t value, unsigned shift) noexcept {
    return std::rotl(value, static_cast<int>(shift & 7U));
}

constexpr std::uint16_t rotl16(std::uint16_t value, unsigned shift) noexcept {
    return std::rotl(value, static_cast<int>(shift & 15U));
}

constexpr std::uint32_t rotl32(std::uint32_t value, unsigned shift) noexcept {
    return std::rotl(value, static_cast<int>(shift & 31U));
}

constexpr std::uint64_t rotl64(std::uint64_t value, unsigned shift) noexcept {
    return std::rotl(value, static_cast<int>(shift & 63U));
}

constexpr std::uint8_t byte_at(std::uint64_t value, unsigned index) noexcept {
    return static_cast<std::uint8_t>(value >> ((index & 7U) * 8U));
}

constexpr std::uint16_t low16(std::uint64_t value) noexcept {
    return static_cast<std::uint16_t>(value);
}

constexpr std::uint16_t high16(std::uint32_t value) noexcept {
    return static_cast<std::uint16_t>(value >> 16U);
}

constexpr std::uint16_t fold64_to16(std::uint64_t value) noexcept {
    const auto mixed = value ^ rotl64(value, 13U) ^ rotl64(value, 37U);
    return static_cast<std::uint16_t>(mixed ^ (mixed >> 16U)
                                     ^ (mixed >> 32U) ^ (mixed >> 48U));
}

constexpr std::uint32_t fold64_to32(std::uint64_t value) noexcept {
    const auto mixed = value ^ rotl64(value, 17U) ^ rotl64(value, 43U);
    return static_cast<std::uint32_t>(mixed ^ (mixed >> 32U));
}

constexpr std::uint16_t fold32_to16(std::uint32_t value) noexcept {
    const auto mixed = value ^ rotl32(value, 7U) ^ rotl32(value, 19U);
    return static_cast<std::uint16_t>(mixed ^ (mixed >> 16U));
}

constexpr std::uint16_t coordinate_word(Coord coord) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(coord.x) << 10U)
                                   | (static_cast<std::uint16_t>(coord.y) << 5U)
                                   | static_cast<std::uint16_t>(coord.z));
}

constexpr std::uint8_t axis_code(Axis axis) noexcept {
    return static_cast<std::uint8_t>(axis);
}

constexpr std::uint8_t domain_code(Domain domain) noexcept {
    return static_cast<std::uint8_t>(domain);
}

constexpr Axis choose_other_axis(Axis previous, bool second) noexcept {
    switch (previous) {
    case Axis::X: return second ? Axis::Z : Axis::Y;
    case Axis::Y: return second ? Axis::X : Axis::Z;
    case Axis::Z: return second ? Axis::Y : Axis::X;
    }
    return Axis::Y;
}

constexpr Coord coord_from_words(Coord cursor,
                                 std::uint16_t control,
                                 std::uint32_t feedback,
                                 std::uint64_t transcript,
                                 std::uint8_t phase,
                                 std::uint8_t domain,
                                 std::uint8_t lane) noexcept {
    const auto c0 = static_cast<std::uint8_t>(control);
    const auto c1 = static_cast<std::uint8_t>(control >> 8U);
    const auto f0 = static_cast<std::uint8_t>(feedback >> ((lane & 3U) * 8U));
    const auto f1 = static_cast<std::uint8_t>(feedback >> (((lane + 1U) & 3U) * 8U));
    const auto t0 = byte_at(transcript, lane);
    const auto t1 = byte_at(transcript, static_cast<unsigned>(lane + 3U));
    const auto x = static_cast<unsigned>(cursor.x) + static_cast<unsigned>(c0)
                 + static_cast<unsigned>(f0) + static_cast<unsigned>(t1)
                 + static_cast<unsigned>(phase) + 3U * static_cast<unsigned>(lane);
    const auto y = static_cast<unsigned>(cursor.y) + static_cast<unsigned>(c1)
                 + static_cast<unsigned>(f1) + static_cast<unsigned>(t0)
                 + 2U * static_cast<unsigned>(phase) + 5U * static_cast<unsigned>(lane);
    const auto z = static_cast<unsigned>(cursor.z) + static_cast<unsigned>(c0 >> 3U)
                 + static_cast<unsigned>(c1 >> 2U) + static_cast<unsigned>(f0 >> 1U)
                 + static_cast<unsigned>(domain) + 3U * static_cast<unsigned>(phase)
                 + 7U * static_cast<unsigned>(lane);
    return Coord{
        static_cast<std::uint8_t>(x & 7U),
        static_cast<std::uint8_t>(y & 7U),
        static_cast<std::uint8_t>(z & 7U),
    };
}

std::array<std::uint8_t, 8> read_line(const Cube& cube, Axis axis, Coord line_point) {
    std::array<std::uint8_t, 8> line{};
    for (std::uint8_t i = 0; i < 8U; ++i) {
        auto coord = line_point;
        switch (axis) {
        case Axis::X: coord.x = i; break;
        case Axis::Y: coord.y = i; break;
        case Axis::Z: coord.z = i; break;
        }
        line[i] = cube.unchecked(coord);
    }
    return line;
}

constexpr std::uint8_t amount_mix_round(std::uint8_t right, unsigned round) noexcept {
    constexpr std::array<std::uint8_t, 6> add_constants{
        0x3DU, 0xA7U, 0x61U, 0xC9U, 0x17U, 0xE3U,
    };
    constexpr std::array<std::uint8_t, 6> multiply_constants{
        0xB5U, 0x6DU, 0xD3U, 0x9BU, 0xF5U, 0x7DU,
    };
    auto value = static_cast<std::uint8_t>(right + add_constants[round]);
    value = static_cast<std::uint8_t>(value * multiply_constants[round]);
    value = static_cast<std::uint8_t>(value ^ rotl8(value, 1U));
    value = static_cast<std::uint8_t>(value + rotl8(right, 3U)
                                    + static_cast<std::uint8_t>(round * 29U + 11U));
    value = static_cast<std::uint8_t>(value ^ (value >> 3U));
    return rotl8(value, round + 1U);
}

constexpr std::uint16_t amount_seed_permutation(std::uint16_t seed) noexcept {
    auto left = static_cast<std::uint8_t>(seed >> 8U);
    auto right = static_cast<std::uint8_t>(seed);
    for (unsigned round = 0; round < 6U; ++round) {
        const auto next_left = right;
        const auto next_right = static_cast<std::uint8_t>(left ^ amount_mix_round(right, round));
        left = next_left;
        right = next_right;
    }
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(left) << 8U) | right);
}

std::array<std::uint8_t, 7> amount_permutation(std::uint16_t seed) {
    // The 16-bit Feistel permutation makes the seed preprocessing bijective.
    // Scaling its output to 7! gives each of the 5,040 permutations exactly
    // 13 or 14 preimages over the complete 2^16 seed domain.
    const auto mixed = amount_seed_permutation(seed);
    std::uint32_t rank = (static_cast<std::uint32_t>(mixed) * 5040U) >> 16U;
    std::array<std::uint8_t, 7> pool{1U, 2U, 3U, 4U, 5U, 6U, 7U};
    std::array<std::uint8_t, 7> output{};
    std::size_t remaining = pool.size();
    constexpr std::array<std::uint32_t, 7> factorial{
        1U, 1U, 2U, 6U, 24U, 120U, 720U,
    };
    for (std::size_t position = 0; position < output.size(); ++position) {
        const auto block = factorial[remaining - 1U];
        const auto index = static_cast<std::size_t>(rank / block);
        rank %= block;
        output[position] = pool[index];
        for (std::size_t j = index; j + 1U < remaining; ++j) {
            pool[j] = pool[j + 1U];
        }
        --remaining;
    }
    return output;
}

std::uint32_t positional_line_feedback(const std::array<std::uint8_t, 8>& before,
                                       const std::array<std::uint8_t, 8>& after,
                                       Axis axis,
                                       std::uint8_t amount,
                                       std::uint8_t phase,
                                       Coord cursor_after) noexcept {
    std::uint32_t value = static_cast<std::uint32_t>(coordinate_word(cursor_after))
                        | (static_cast<std::uint32_t>(axis_code(axis)) << 16U)
                        | (static_cast<std::uint32_t>(amount) << 20U)
                        | (static_cast<std::uint32_t>(phase) << 24U);
    for (std::size_t i = 0; i < before.size(); ++i) {
        const auto partner = (i + amount + axis_code(axis) + phase) & 7U;
        const auto lane = static_cast<std::uint32_t>(before[i])
                        | (static_cast<std::uint32_t>(after[partner]) << 8U)
                        | (static_cast<std::uint32_t>(i * 29U + partner * 17U) << 16U);
        value = rotl32(value ^ lane, static_cast<unsigned>(3U + i + amount))
              + rotl32(lane + static_cast<std::uint32_t>(0x01010101U * (i + 1U)),
                       static_cast<unsigned>(1U + partner));
    }
    return value;
}

ControllerState inject_symbol(const WorkingState& state,
                              std::uint8_t symbol,
                              Domain domain) noexcept {
    const auto dc = domain_code(domain);
    const auto index_low = static_cast<std::uint16_t>(state.symbol_index);
    const auto index_fold = static_cast<std::uint16_t>(state.symbol_index
                                                     ^ (state.symbol_index >> 16U)
                                                     ^ (state.symbol_index >> 32U));
    ControllerState c = state.controller;
    const auto symbol_word = static_cast<std::uint16_t>(symbol)
                           | (static_cast<std::uint16_t>(rotl8(symbol, 3U)) << 8U);
    const auto domain_word = static_cast<std::uint16_t>(dc)
                           | (static_cast<std::uint16_t>(rotl8(dc, 5U)) << 8U);
    const auto transcript_fold = fold64_to16(c.transcript);
    const auto transcript_wide_fold = fold64_to32(c.transcript);
    const auto feedback_axis_fold = fold32_to16(c.feedback);
    const auto feedback_amount_fold = fold32_to16(rotl32(c.feedback, 11U));
    c.axis_control = static_cast<std::uint16_t>(
        rotl16(static_cast<std::uint16_t>(c.axis_control ^ symbol_word ^ index_fold
                                         ^ feedback_axis_fold),
               3U + (state.symbol_index & 7U))
        + rotl16(transcript_fold, 1U + (state.symbol_index & 15U))
        + coordinate_word(state.cursor)
        + domain_word);
    c.amount_control = static_cast<std::uint16_t>(
        rotl16(static_cast<std::uint16_t>(c.amount_control + symbol_word + index_low),
               5U + ((state.symbol_index >> 1U) & 7U))
        ^ high16(c.feedback)
        ^ feedback_amount_fold
        ^ rotl16(c.axis_control, 7U)
        ^ rotl16(transcript_fold, 9U + ((symbol ^ dc) & 7U))
        ^ static_cast<std::uint16_t>(static_cast<unsigned>(domain_word) + 0x4B39U));
    const auto event = static_cast<std::uint32_t>(symbol_word)
                     | (static_cast<std::uint32_t>(domain_word) << 16U);
    c.feedback = rotl32(c.feedback ^ event ^ coordinate_word(state.cursor)
                        ^ transcript_wide_fold,
                        7U + static_cast<unsigned>(state.symbol_index & 15U))
               + static_cast<std::uint32_t>(c.axis_control) * 257U
               + static_cast<std::uint32_t>(c.amount_control) * 263U;
    const auto wide_event = static_cast<std::uint64_t>(event)
                          | (static_cast<std::uint64_t>(index_fold) << 32U)
                          | (static_cast<std::uint64_t>(coordinate_word(state.cursor)) << 48U);
    c.transcript = rotl64(c.transcript ^ wide_event,
                          11U + static_cast<unsigned>((dc ^ symbol) & 31U))
                 + rotl64(static_cast<std::uint64_t>(c.feedback) << 16U
                          | static_cast<std::uint64_t>(c.axis_control), 23U)
                 + static_cast<std::uint64_t>(c.amount_control) * 0x0001000100010001ULL;
    return c;
}

} // namespace

WorkingState make_initial_state(std::uint64_t research_seed) {
    WorkingState state;
    const auto& d = Cube::perfect_body_diagonals();
    const auto seed_lo = static_cast<std::uint32_t>(research_seed);
    const auto seed_hi = static_cast<std::uint32_t>(research_seed >> 32U);
    state.cursor = Coord{
        static_cast<std::uint8_t>((research_seed ^ d[3]) & 7U),
        static_cast<std::uint8_t>(((research_seed >> 11U) ^ d[12]) & 7U),
        static_cast<std::uint8_t>(((research_seed >> 23U) ^ d[21]) & 7U),
    };
    state.previous_axis = static_cast<Axis>((research_seed + d[7]) % 3U);
    state.controller.axis_control = static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(low16(research_seed)
        ^ static_cast<std::uint16_t>(static_cast<std::uint16_t>(d[0]) << 8U)
        ^ static_cast<std::uint16_t>(d[9])
        ^ static_cast<std::uint16_t>(0x6D35U)));
    state.controller.amount_control = static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(low16(research_seed >> 16U)
        ^ static_cast<std::uint16_t>(static_cast<std::uint16_t>(d[17]) << 8U)
        ^ static_cast<std::uint16_t>(d[26])
        ^ static_cast<std::uint16_t>(0xB7E1U)));
    state.controller.feedback = rotl32(seed_lo ^ 0xD1A56E2BU, 9U)
                              + rotl32(seed_hi ^ 0x3C8F725DU, 17U)
                              + coordinate_word(state.cursor);
    state.controller.transcript = rotl64(research_seed ^ 0x6B5D39A7C2E14F83ULL, 19U)
                                + (static_cast<std::uint64_t>(state.controller.feedback) << 16U)
                                + state.controller.axis_control
                                + (static_cast<std::uint64_t>(state.controller.amount_control) << 48U);
    return state;
}

void enter_domain(WorkingState& state, Domain domain, std::uint64_t sequence_length) {
    const auto dc = domain_code(domain);
    const auto diagonals = state.cube.body_diagonals();
    const auto i0 = static_cast<std::size_t>((state.controller.feedback ^ sequence_length ^ dc) & 31U);
    const auto i1 = static_cast<std::size_t>((state.controller.transcript >> 13U) + dc * 7U) & 31U;
    const auto i2 = static_cast<std::size_t>((state.controller.transcript >> 37U) + dc * 11U) & 31U;
    const auto d0 = diagonals[i0];
    const auto d1 = diagonals[i1];
    const auto d2 = diagonals[i2];
    const auto length_word = static_cast<std::uint16_t>(sequence_length
                                                       ^ (sequence_length >> 16U)
                                                       ^ (sequence_length >> 32U));
    const auto domain_word = static_cast<std::uint16_t>(dc)
                           | (static_cast<std::uint16_t>(rotl8(dc, 3U)) << 8U);

    const auto old_axis = state.controller.axis_control;
    const auto old_amount = state.controller.amount_control;
    const auto old_feedback = state.controller.feedback;
    const auto old_transcript = state.controller.transcript;

    state.controller.axis_control = static_cast<std::uint16_t>(
        rotl16(static_cast<std::uint16_t>(old_axis ^ length_word
                                         ^ (static_cast<std::uint16_t>(d0) << 8U | d1)),
               5U + (dc & 7U))
        + static_cast<std::uint16_t>(old_transcript)
        + domain_word);
    state.controller.amount_control = static_cast<std::uint16_t>(
        rotl16(static_cast<std::uint16_t>(old_amount + length_word
                                         + (static_cast<std::uint16_t>(d1) << 8U | d2)),
               9U + ((dc >> 2U) & 7U))
        ^ static_cast<std::uint16_t>(old_feedback >> 16U)
        ^ rotl16(old_axis, 3U)
        ^ static_cast<std::uint16_t>(static_cast<unsigned>(domain_word) + 0x2F6BU));
    const auto boundary = static_cast<std::uint32_t>(d0)
                        | (static_cast<std::uint32_t>(d1) << 8U)
                        | (static_cast<std::uint32_t>(d2) << 16U)
                        | (static_cast<std::uint32_t>(dc) << 24U);
    state.controller.feedback = rotl32(old_feedback ^ boundary, 11U + (dc & 15U))
                              + static_cast<std::uint32_t>(state.controller.axis_control) * 269U
                              + static_cast<std::uint32_t>(state.controller.amount_control) * 271U
                              + static_cast<std::uint32_t>(sequence_length);
    state.controller.transcript = rotl64(old_transcript ^ sequence_length
                                         ^ (static_cast<std::uint64_t>(boundary) << 17U),
                                         17U + (dc & 31U))
                                + (static_cast<std::uint64_t>(state.controller.feedback) << 29U)
                                + (static_cast<std::uint64_t>(state.controller.axis_control) << 7U)
                                + state.controller.amount_control;
}

MoveDecision preview_move(const WorkingState& state,
                          std::uint8_t symbol,
                          Domain domain,
                          std::uint8_t phase) {
    const auto injected = inject_symbol(state, symbol, domain);
    const auto dc = domain_code(domain);

    ProbeSet probes;
    probes.axis_coord_0 = coord_from_words(state.cursor, injected.axis_control,
                                          injected.feedback, injected.transcript,
                                          phase, dc, 0U);
    probes.axis_coord_1 = coord_from_words(state.cursor,
                                          rotl16(injected.axis_control, 7U),
                                          rotl32(injected.feedback, 11U),
                                          rotl64(injected.transcript, 19U),
                                          phase, dc, 3U);
    probes.amount_coord_0 = coord_from_words(state.cursor, injected.amount_control,
                                            rotl32(injected.feedback, 17U),
                                            rotl64(injected.transcript, 29U),
                                            phase, dc, 5U);
    probes.amount_coord_1 = coord_from_words(state.cursor,
                                            rotl16(injected.amount_control, 9U),
                                            rotl32(injected.feedback, 23U),
                                            rotl64(injected.transcript, 41U),
                                            phase, dc, 7U);
    probes.axis_probe_0 = state.cube.unchecked(probes.axis_coord_0);
    probes.axis_probe_1 = state.cube.unchecked(probes.axis_coord_1);
    probes.amount_probe_0 = state.cube.unchecked(probes.amount_coord_0);
    probes.amount_probe_1 = state.cube.unchecked(probes.amount_coord_1);

    const auto axis_pack = static_cast<std::uint16_t>(probes.axis_probe_0)
                         | (static_cast<std::uint16_t>(probes.axis_probe_1) << 8U);
    const auto axis_word = static_cast<std::uint16_t>(
        rotl16(static_cast<std::uint16_t>(injected.axis_control ^ axis_pack),
               1U + ((phase + probes.axis_probe_0) & 15U))
        + static_cast<std::uint16_t>(injected.feedback)
        + coordinate_word(state.cursor)
        + static_cast<std::uint16_t>(dc * 193U + phase * 71U));
    const auto axis_data = static_cast<std::uint8_t>(axis_word ^ (axis_word >> 8U)
                                                     ^ rotl8(probes.axis_probe_0, 1U)
                                                     ^ rotl8(probes.axis_probe_1, 5U)
                                                     ^ byte_at(injected.transcript, phase));
    const auto axis_bit_index = static_cast<unsigned>(probes.axis_probe_1
                                                     + byte_at(injected.transcript, phase + 2U)
                                                     + phase + dc) & 7U;
    const auto control_bit_index = static_cast<unsigned>(probes.axis_probe_0
                                                        + phase + dc) & 15U;
    const auto selector_bit = static_cast<std::uint8_t>(
        ((axis_data >> axis_bit_index)
         ^ (injected.axis_control >> control_bit_index)
         ^ (injected.feedback >> ((axis_bit_index + 11U) & 31U))) & 1U);
    const auto axis = choose_other_axis(state.previous_axis, selector_bit != 0U);

    const auto amount_pack = static_cast<std::uint16_t>(probes.amount_probe_0)
                           | (static_cast<std::uint16_t>(probes.amount_probe_1) << 8U);
    const auto amount_word = static_cast<std::uint16_t>(
        rotl16(static_cast<std::uint16_t>(injected.amount_control + amount_pack
                                         + rotl16(injected.axis_control, 5U)),
               3U + ((phase + probes.amount_probe_1) & 15U))
        ^ static_cast<std::uint16_t>(injected.feedback >> 16U)
        ^ static_cast<std::uint16_t>(byte_at(injected.transcript, phase + 4U) * 257U)
        ^ static_cast<std::uint16_t>(axis_code(axis) * 0x2D3BU + dc * 0x013DU));
    const auto perm_seed = static_cast<std::uint16_t>(
        amount_word
        ^ rotl16(static_cast<std::uint16_t>(amount_pack + coordinate_word(state.cursor)),
                 7U + axis_code(axis))
        ^ static_cast<std::uint16_t>(injected.transcript >> ((phase & 3U) * 16U)));
    const auto permutation = amount_permutation(perm_seed);
    std::uint8_t amount_slot = static_cast<std::uint8_t>(
        (amount_word
         ^ rotl16(injected.amount_control, probes.amount_probe_0 & 15U)
         ^ static_cast<std::uint16_t>(probes.amount_probe_1 * 257U)
         ^ static_cast<std::uint16_t>(injected.feedback >> ((phase & 1U) * 16U))) & 7U);
    if (amount_slot == 7U) {
        const auto folded_slot = static_cast<unsigned>(probes.amount_probe_0)
                               + static_cast<unsigned>(rotl8(probes.amount_probe_1, 3U))
                               + static_cast<unsigned>(byte_at(injected.transcript, phase + 6U))
                               + static_cast<unsigned>(axis_code(axis))
                               + static_cast<unsigned>(phase);
        amount_slot = static_cast<std::uint8_t>(folded_slot % 7U);
    }

    return MoveDecision{
        .axis = axis,
        .amount = permutation[amount_slot],
        .axis_word = axis_word,
        .amount_word = amount_word,
        .axis_selector_bit = selector_bit,
        .amount_slot = amount_slot,
        .amount_permutation_seed = perm_seed,
        .amount_permutation = permutation,
        .probes = probes,
    };
}

MoveTrace apply_move(WorkingState& state,
                     std::uint8_t symbol,
                     Domain domain,
                     std::uint8_t phase) {
    const auto injected = inject_symbol(state, symbol, domain);
    // preview_move performs the same symbol injection from state; keep it as the
    // single decision definition and use its result here.
    const auto decision = preview_move(state, symbol, domain, phase);
    const auto controller_before = state.controller;
    const auto cursor_before = state.cursor;
    const auto previous_axis = state.previous_axis;
    const auto line_before = read_line(state.cube, decision.axis, state.cursor);

    state.cube.rotate_line(decision.axis, state.cursor, decision.amount);
    state.cursor = advance(state.cursor, decision.axis, decision.amount);
    const auto line_after = read_line(state.cube, decision.axis, state.cursor);
    const auto line_feedback = positional_line_feedback(line_before, line_after,
                                                        decision.axis, decision.amount,
                                                        phase, state.cursor);

    const auto post_axis_probe = state.cube.unchecked(decision.probes.axis_coord_1);
    const auto post_amount_probe = state.cube.unchecked(decision.probes.amount_coord_1);
    const auto dc = domain_code(domain);
    const auto event16 = static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(symbol)
        | (static_cast<std::uint16_t>(phase ^ dc) << 8U));
    const auto event32 = static_cast<std::uint32_t>(event16)
                       | (static_cast<std::uint32_t>(coordinate_word(state.cursor)) << 16U);

    ControllerState next;
    next.feedback = rotl32(injected.feedback ^ line_feedback ^ event32,
                           5U + decision.amount + axis_code(decision.axis))
                  + static_cast<std::uint32_t>(decision.axis_word) * 277U
                  + static_cast<std::uint32_t>(decision.amount_word) * 281U
                  + static_cast<std::uint32_t>(post_axis_probe) * 0x01010101U
                  + static_cast<std::uint32_t>(post_amount_probe) * 0x00010001U;
    next.axis_control = static_cast<std::uint16_t>(
        rotl16(static_cast<std::uint16_t>(injected.axis_control
                                         + decision.axis_word
                                         + static_cast<std::uint16_t>(next.feedback)),
               3U + decision.amount)
        ^ rotl16(injected.amount_control, 5U + axis_code(decision.axis))
        ^ static_cast<std::uint16_t>(post_axis_probe * 257U)
        ^ event16);
    next.amount_control = static_cast<std::uint16_t>(
        rotl16(static_cast<std::uint16_t>(injected.amount_control
                                         ^ decision.amount_word
                                         ^ static_cast<std::uint16_t>(next.feedback >> 16U)),
               7U + axis_code(decision.axis) + phase)
        + rotl16(injected.axis_control, 9U + decision.amount)
        + static_cast<std::uint16_t>(post_amount_probe * 257U)
        + static_cast<std::uint16_t>(coordinate_word(state.cursor) ^ event16));
    const auto event64 = static_cast<std::uint64_t>(line_feedback)
                       | (static_cast<std::uint64_t>(event32) << 32U);
    next.transcript = rotl64(injected.transcript ^ event64,
                             13U + decision.amount + 7U * axis_code(decision.axis))
                    + rotl64(static_cast<std::uint64_t>(next.feedback) << 16U
                             | next.axis_control, 29U)
                    + static_cast<std::uint64_t>(next.amount_control) * 0x0001000100010001ULL
                    + (static_cast<std::uint64_t>(decision.probes.axis_probe_0) << 7U)
                    + (static_cast<std::uint64_t>(decision.probes.amount_probe_0) << 47U);

    state.controller = next;
    state.previous_axis = decision.axis;

    return MoveTrace{
        .symbol_index = state.symbol_index,
        .phase = phase,
        .symbol = symbol,
        .domain = domain,
        .cursor_before = cursor_before,
        .cursor_after = state.cursor,
        .previous_axis = previous_axis,
        .decision = decision,
        .controller_before = controller_before,
        .controller_after = next,
        .line_feedback = line_feedback,
    };
}

void absorb_symbol(WorkingState& state,
                   std::uint8_t symbol,
                   Domain domain,
                   std::size_t moves_per_symbol,
                   std::vector<MoveTrace>* trace) {
    if (moves_per_symbol == 0U || moves_per_symbol > 255U) {
        throw std::invalid_argument("moves_per_symbol must be in [1,255]");
    }
    for (std::size_t phase = 0; phase < moves_per_symbol; ++phase) {
        auto move = apply_move(state, symbol, domain, static_cast<std::uint8_t>(phase));
        if (trace != nullptr) {
            trace->push_back(std::move(move));
        }
    }
    ++state.symbol_index;
}

void absorb_sequence(WorkingState& state,
                     std::span<const std::uint8_t> symbols,
                     Domain domain,
                     std::size_t moves_per_symbol,
                     std::vector<MoveTrace>* trace) {
    for (const auto symbol : symbols) {
        absorb_symbol(state, symbol, domain, moves_per_symbol, trace);
    }
}

std::size_t cube_byte_distance(const Cube& left, const Cube& right) {
    std::size_t distance = 0;
    for (std::size_t i = 0; i < kCubeCells; ++i) {
        distance += left.storage()[i] != right.storage()[i] ? 1U : 0U;
    }
    return distance;
}

std::size_t controller_bit_distance(const ControllerState& left,
                                    const ControllerState& right) {
    return static_cast<std::size_t>(std::popcount(static_cast<std::uint16_t>(
               left.axis_control ^ right.axis_control)))
         + static_cast<std::size_t>(std::popcount(static_cast<std::uint16_t>(
               left.amount_control ^ right.amount_control)))
         + static_cast<std::size_t>(std::popcount(left.feedback ^ right.feedback))
         + static_cast<std::size_t>(std::popcount(left.transcript ^ right.transcript));
}

std::uint64_t state_fingerprint(const WorkingState& state) {
    std::uint64_t value = state.controller.transcript
                        ^ (static_cast<std::uint64_t>(state.controller.feedback) << 17U)
                        ^ (static_cast<std::uint64_t>(state.controller.axis_control) << 1U)
                        ^ (static_cast<std::uint64_t>(state.controller.amount_control) << 33U)
                        ^ (static_cast<std::uint64_t>(coordinate_word(state.cursor)) << 49U)
                        ^ state.symbol_index;
    for (std::size_t i = 0; i < state.cube.storage().size(); ++i) {
        value = rotl64(value ^ static_cast<std::uint64_t>(state.cube.storage()[i])
                              ^ static_cast<std::uint64_t>(i * 131U),
                       static_cast<unsigned>(1U + (i & 31U)))
              + static_cast<std::uint64_t>(state.cube.storage()[i]) * (257U + 2U * i);
    }
    return value;
}

const char* domain_name(Domain domain) {
    switch (domain) {
    case Domain::KeyForward: return "key-forward";
    case Domain::KeyReturn: return "key-return";
    case Domain::KeySeal: return "key-seal";
    case Domain::InputForward: return "input-forward";
    case Domain::InputReturn: return "input-return";
    case Domain::ReturnInit: return "return-init";
    case Domain::ReturnSeal: return "return-seal";
    case Domain::Finalization: return "finalization";
    case Domain::Squeeze: return "squeeze";
    }
    return "unknown";
}


std::array<std::uint8_t, 7> research_amount_permutation(std::uint16_t seed) {
    return amount_permutation(seed);
}

} // namespace pvc1
