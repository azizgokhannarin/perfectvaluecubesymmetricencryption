#include "pvc1/controller_b.hpp"

#include <array>
#include <bit>
#include <limits>
#include <stdexcept>

namespace pvc1 {
namespace {

constexpr std::uint8_t rotl8(std::uint8_t value, unsigned shift) noexcept {
    return std::rotl(value, static_cast<int>(shift & 7U));
}
constexpr std::uint32_t rotl32(std::uint32_t value, unsigned shift) noexcept {
    return std::rotl(value, static_cast<int>(shift & 31U));
}
constexpr std::uint64_t rotl64(std::uint64_t value, unsigned shift) noexcept {
    return std::rotl(value, static_cast<int>(shift & 63U));
}
constexpr std::uint8_t axis_code(Axis axis) noexcept {
    return static_cast<std::uint8_t>(axis);
}
constexpr std::uint8_t domain_code(Domain domain) noexcept {
    return static_cast<std::uint8_t>(domain);
}
constexpr std::uint16_t coordinate_word(Coord coord) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(coord.x) << 10U)
                                   | (static_cast<std::uint16_t>(coord.y) << 5U)
                                   | static_cast<std::uint16_t>(coord.z));
}
constexpr Axis other_axis(Axis previous, bool second) noexcept {
    switch (previous) {
    case Axis::X: return second ? Axis::Z : Axis::Y;
    case Axis::Y: return second ? Axis::X : Axis::Z;
    case Axis::Z: return second ? Axis::Y : Axis::X;
    }
    return Axis::Y;
}

constexpr std::uint32_t mix32(std::uint32_t a,
                              std::uint32_t b,
                              std::uint32_t c,
                              unsigned rotation) noexcept {
    auto x = rotl32(a + 0x9E3779B9U + c, rotation);
    x ^= rotl32(b + 0x7F4A7C15U, rotation + 11U);
    x += rotl32(c ^ 0xD1B54A35U, rotation + 19U);
    x ^= x >> 13U;
    x *= 0x85EBCA6BU;
    x ^= rotl32(x, 7U) ^ (x >> 16U);
    return x;
}

constexpr std::uint32_t fold64(std::uint64_t value) noexcept {
    return static_cast<std::uint32_t>(value ^ (value >> 32U)
                                    ^ rotl64(value, 17U)
                                    ^ rotl64(value, 41U));
}

Coord coordinate_b(Coord cursor,
                   std::uint32_t a,
                   std::uint32_t b,
                   std::uint64_t path,
                   std::uint8_t phase,
                   std::uint8_t dc,
                   std::uint8_t lane) noexcept {
    const auto p = fold64(rotl64(path, static_cast<unsigned>(lane * 9U + phase)));
    const auto m0 = mix32(a, b, p ^ static_cast<std::uint32_t>(dc), 3U + lane);
    const auto m1 = mix32(b, p, a ^ static_cast<std::uint32_t>(phase), 11U + lane);
    return Coord{
        static_cast<std::uint8_t>((static_cast<unsigned>(cursor.x) + (m0 & 7U)) & 7U),
        static_cast<std::uint8_t>((static_cast<unsigned>(cursor.y) + ((m0 >> 11U) & 7U)
                                  + lane) & 7U),
        static_cast<std::uint8_t>((static_cast<unsigned>(cursor.z) + ((m1 >> 21U) & 7U)
                                  + phase + dc) & 7U),
    };
}

std::array<std::uint8_t, 8> read_line(const Cube& cube, Axis axis, Coord point) {
    std::array<std::uint8_t, 8> line{};
    for (std::uint8_t i = 0; i < 8U; ++i) {
        auto coord = point;
        if (axis == Axis::X) coord.x = i;
        if (axis == Axis::Y) coord.y = i;
        if (axis == Axis::Z) coord.z = i;
        line[i] = cube.unchecked(coord);
    }
    return line;
}

std::uint32_t line_feedback_b(const std::array<std::uint8_t, 8>& before,
                              const std::array<std::uint8_t, 8>& after,
                              Axis axis,
                              std::uint8_t amount,
                              std::uint8_t phase,
                              Coord cursor) noexcept {
    auto value = static_cast<std::uint32_t>(coordinate_word(cursor))
               | (static_cast<std::uint32_t>(axis_code(axis)) << 16U)
               | (static_cast<std::uint32_t>(amount) << 20U)
               | (static_cast<std::uint32_t>(phase) << 24U);
    for (std::size_t i = 0; i < before.size(); ++i) {
        const auto j = (7U + amount + axis_code(axis) - static_cast<unsigned>(i)) & 7U;
        const auto event = static_cast<std::uint32_t>(before[i])
                         | (static_cast<std::uint32_t>(after[j]) << 8U)
                         | (static_cast<std::uint32_t>(i * 37U + j * 23U) << 16U);
        value = mix32(value, event, static_cast<std::uint32_t>(i + 1U) * 0x01020408U,
                      static_cast<unsigned>(5U + i + amount));
    }
    return value;
}

ControllerStateB inject_symbol_b(const WorkingStateB& state,
                                 std::uint8_t symbol,
                                 Domain domain) noexcept {
    const auto dc = domain_code(domain);
    const auto index = state.symbol_index;
    const auto index_fold = static_cast<std::uint32_t>(index ^ (index >> 32U));
    const auto event0 = static_cast<std::uint32_t>(symbol)
                      | (static_cast<std::uint32_t>(rotl8(symbol, 3U)) << 8U)
                      | (static_cast<std::uint32_t>(dc) << 16U)
                      | (static_cast<std::uint32_t>(rotl8(dc, 5U)) << 24U);
    const auto event1 = index_fold
                      ^ (static_cast<std::uint32_t>(coordinate_word(state.cursor)) << 11U)
                      ^ fold64(state.controller.path);
    const auto old = state.controller.lane;
    ControllerStateB next;
    next.lane[0] = mix32(old[0] + event0, old[2] ^ event1, old[3], 5U + static_cast<unsigned>(index & 7U));
    next.lane[1] = mix32(old[1] ^ event1, old[3] + event0, next.lane[0], 11U + (symbol & 7U));
    next.lane[2] = mix32(old[2] + ~event0, old[0] ^ rotl32(event1, 9U), next.lane[1], 17U + (dc & 7U));
    next.lane[3] = mix32(old[3] ^ rotl32(event0, 13U), old[1] + event1, next.lane[2], 23U + ((symbol ^ dc) & 7U));
    const auto left = static_cast<std::uint64_t>(next.lane[0])
                    | (static_cast<std::uint64_t>(next.lane[2]) << 32U);
    const auto right = static_cast<std::uint64_t>(next.lane[1])
                     | (static_cast<std::uint64_t>(next.lane[3]) << 32U);
    next.path = rotl64(state.controller.path ^ left ^ (static_cast<std::uint64_t>(event0) << 17U),
                       19U + static_cast<unsigned>((index + dc) & 31U))
              + rotl64(right ^ static_cast<std::uint64_t>(event1), 37U)
              + 0xA0761D6478BD642FULL;
    return next;
}

} // namespace

WorkingStateB make_initial_state_b(std::uint64_t research_seed) {
    WorkingStateB state;
    const auto& d = Cube::perfect_body_diagonals();
    state.cursor = Coord{
        static_cast<std::uint8_t>((research_seed ^ d[2]) & 7U),
        static_cast<std::uint8_t>(((research_seed >> 9U) ^ d[15]) & 7U),
        static_cast<std::uint8_t>(((research_seed >> 27U) ^ d[28]) & 7U),
    };
    state.previous_axis = static_cast<Axis>((research_seed + d[19]) % 3U);
    const auto lo = static_cast<std::uint32_t>(research_seed);
    const auto hi = static_cast<std::uint32_t>(research_seed >> 32U);
    state.controller.lane[0] = mix32(lo, hi, 0x243F6A88U ^ d[0], 5U);
    state.controller.lane[1] = mix32(hi, lo, 0x85A308D3U ^ d[9], 11U);
    state.controller.lane[2] = mix32(lo ^ 0x13198A2EU, hi + d[18], 0x03707344U, 17U);
    state.controller.lane[3] = mix32(hi ^ 0xA4093822U, lo + d[27], 0x299F31D0U, 23U);
    state.controller.path = rotl64(research_seed ^ 0x082EFA98EC4E6C89ULL, 29U)
                          + (static_cast<std::uint64_t>(state.controller.lane[0]) << 32U)
                          + state.controller.lane[3];
    return state;
}

void enter_domain_b(WorkingStateB& state, Domain domain, std::uint64_t sequence_length) {
    const auto dc = domain_code(domain);
    const auto d = state.cube.body_diagonals();
    const auto old = state.controller.lane;
    const auto path_fold = fold64(state.controller.path ^ sequence_length);
    const auto length_fold = static_cast<std::uint32_t>(sequence_length ^ (sequence_length >> 32U));
    for (std::size_t i = 0; i < 4U; ++i) {
        const auto p0 = d[(static_cast<std::size_t>(old[i]) + i * 7U + dc) & 31U];
        const auto p1 = d[(static_cast<std::size_t>(old[(i + 2U) & 3U] >> 11U)
                          + i * 13U + dc) & 31U];
        const auto boundary = static_cast<std::uint32_t>(p0)
                            | (static_cast<std::uint32_t>(p1) << 8U)
                            | (static_cast<std::uint32_t>(dc) << 16U)
                            | (static_cast<std::uint32_t>(i) << 24U);
        state.controller.lane[i] = mix32(old[i] ^ boundary,
                                         old[(i + 1U) & 3U] + length_fold,
                                         path_fold ^ old[(i + 3U) & 3U],
                                         static_cast<unsigned>(7U + i * 6U + (dc & 3U)));
    }
    const auto left = static_cast<std::uint64_t>(state.controller.lane[0])
                    | (static_cast<std::uint64_t>(state.controller.lane[2]) << 32U);
    const auto right = static_cast<std::uint64_t>(state.controller.lane[1])
                     | (static_cast<std::uint64_t>(state.controller.lane[3]) << 32U);
    state.controller.path = rotl64(state.controller.path ^ sequence_length ^ left,
                                   13U + (dc & 31U))
                          + rotl64(right, 43U)
                          + static_cast<std::uint64_t>(dc) * 0x0101010101010101ULL;
}

MoveDecisionB preview_move_b(const WorkingStateB& state,
                             std::uint8_t symbol,
                             Domain domain,
                             std::uint8_t phase) {
    const auto injected = inject_symbol_b(state, symbol, domain);
    const auto dc = domain_code(domain);
    ProbeSetB probes;
    probes.axis_coord_0 = coordinate_b(state.cursor, injected.lane[0], injected.lane[2],
                                       injected.path, phase, dc, 0U);
    probes.axis_coord_1 = coordinate_b(state.cursor, injected.lane[2], injected.lane[0],
                                       rotl64(injected.path, 23U), phase, dc, 3U);
    probes.amount_coord_0 = coordinate_b(state.cursor, injected.lane[1], injected.lane[3],
                                         rotl64(injected.path, 31U), phase, dc, 5U);
    probes.amount_coord_1 = coordinate_b(state.cursor, injected.lane[3], injected.lane[1],
                                         rotl64(injected.path, 47U), phase, dc, 7U);
    probes.axis_probe_0 = state.cube.unchecked(probes.axis_coord_0);
    probes.axis_probe_1 = state.cube.unchecked(probes.axis_coord_1);
    probes.amount_probe_0 = state.cube.unchecked(probes.amount_coord_0);
    probes.amount_probe_1 = state.cube.unchecked(probes.amount_coord_1);

    const auto first_axis = other_axis(state.previous_axis, false);
    const auto second_axis = other_axis(state.previous_axis, true);
    const auto path_fold = fold64(injected.path);
    const auto axis_event = static_cast<std::uint32_t>(probes.axis_probe_0)
                          | (static_cast<std::uint32_t>(probes.axis_probe_1) << 8U)
                          | (static_cast<std::uint32_t>(phase) << 16U)
                          | (static_cast<std::uint32_t>(dc) << 24U);
    std::array<std::uint32_t, 2> axis_scores{
        mix32(injected.lane[0], injected.lane[2] ^ axis_event,
              path_fold + axis_code(first_axis) * 0x9E3779B9U, 7U),
        mix32(injected.lane[2], injected.lane[0] + axis_event,
              rotl32(path_fold, 13U) + axis_code(second_axis) * 0x7F4A7C15U, 19U),
    };
    const auto axis = axis_scores[1] < axis_scores[0] ? second_axis : first_axis;

    std::array<std::uint32_t, 7> amount_scores{};
    std::array<std::uint8_t, 7> candidate_probes{};
    auto best = std::numeric_limits<std::uint32_t>::max();
    std::uint8_t selected = 1U;
    for (std::uint8_t candidate = 1U; candidate <= 7U; ++candidate) {
        auto coord = probes.amount_coord_0;
        coord.x = static_cast<std::uint8_t>((static_cast<unsigned>(coord.x)
                                               + static_cast<unsigned>(candidate)
                                               + static_cast<unsigned>(axis_code(axis))) & 7U);
        coord.y = static_cast<std::uint8_t>((static_cast<unsigned>(coord.y)
                                               + 3U * static_cast<unsigned>(candidate)
                                               + static_cast<unsigned>(phase)) & 7U);
        coord.z = static_cast<std::uint8_t>((static_cast<unsigned>(coord.z)
                                               + 5U * static_cast<unsigned>(candidate)
                                               + static_cast<unsigned>(dc)) & 7U);
        const auto probe = state.cube.unchecked(coord);
        candidate_probes[candidate - 1U] = probe;
        const auto event = static_cast<std::uint32_t>(probes.amount_probe_0)
                         | (static_cast<std::uint32_t>(probes.amount_probe_1) << 8U)
                         | (static_cast<std::uint32_t>(probe) << 16U)
                         | (static_cast<std::uint32_t>(candidate) << 24U);
        const auto score = mix32(injected.lane[1] + candidate * 0x9E3779B9U,
                                 injected.lane[3] ^ rotl32(event, candidate),
                                 path_fold + event + axis_code(axis) * 0xD1B54A35U,
                                 static_cast<unsigned>(3U + candidate * 4U + phase));
        amount_scores[candidate - 1U] = score;
        if (score < best) {
            best = score;
            selected = candidate;
        }
    }

    return MoveDecisionB{
        .axis = axis,
        .amount = selected,
        .axis_scores = axis_scores,
        .amount_scores = amount_scores,
        .candidate_probes = candidate_probes,
        .probes = probes,
    };
}

MoveTraceB apply_move_b(WorkingStateB& state,
                        std::uint8_t symbol,
                        Domain domain,
                        std::uint8_t phase) {
    const auto injected = inject_symbol_b(state, symbol, domain);
    const auto decision = preview_move_b(state, symbol, domain, phase);
    const auto before_controller = state.controller;
    const auto before_cursor = state.cursor;
    const auto previous_axis = state.previous_axis;
    const auto before_line = read_line(state.cube, decision.axis, state.cursor);
    state.cube.rotate_line(decision.axis, state.cursor, decision.amount);
    state.cursor = advance(state.cursor, decision.axis, decision.amount);
    const auto after_line = read_line(state.cube, decision.axis, state.cursor);
    const auto feedback = line_feedback_b(before_line, after_line, decision.axis,
                                          decision.amount, phase, state.cursor);
    const auto post0 = state.cube.unchecked(decision.probes.axis_coord_1);
    const auto post1 = state.cube.unchecked(decision.probes.amount_coord_1);
    const auto event = static_cast<std::uint32_t>(symbol)
                     | (static_cast<std::uint32_t>(phase) << 8U)
                     | (static_cast<std::uint32_t>(domain_code(domain)) << 16U)
                     | (static_cast<std::uint32_t>(decision.amount) << 24U);

    ControllerStateB next;
    next.lane[0] = mix32(injected.lane[0] ^ feedback,
                         injected.lane[1] + event,
                         injected.lane[3] ^ post0, 5U + decision.amount);
    next.lane[1] = mix32(injected.lane[1] + rotl32(feedback, 7U),
                         injected.lane[2] ^ event,
                         next.lane[0] + post1, 11U + axis_code(decision.axis));
    next.lane[2] = mix32(injected.lane[2] ^ rotl32(feedback, 13U),
                         injected.lane[3] + event,
                         next.lane[1] ^ coordinate_word(state.cursor),
                         17U + phase);
    next.lane[3] = mix32(injected.lane[3] + rotl32(feedback, 19U),
                         injected.lane[0] ^ event,
                         next.lane[2] + post0 * 257U + post1,
                         23U + decision.amount + axis_code(decision.axis));
    const auto left = static_cast<std::uint64_t>(next.lane[0])
                    | (static_cast<std::uint64_t>(next.lane[2]) << 32U);
    const auto right = static_cast<std::uint64_t>(next.lane[1])
                     | (static_cast<std::uint64_t>(next.lane[3]) << 32U);
    next.path = rotl64(injected.path ^ left ^ static_cast<std::uint64_t>(feedback),
                       17U + decision.amount)
              + rotl64(right ^ (static_cast<std::uint64_t>(event) << 29U),
                       41U + axis_code(decision.axis))
              + static_cast<std::uint64_t>(coordinate_word(state.cursor)) * 0x0001000100010001ULL;

    state.controller = next;
    state.previous_axis = decision.axis;
    return MoveTraceB{
        .symbol_index = state.symbol_index,
        .phase = phase,
        .symbol = symbol,
        .domain = domain,
        .cursor_before = before_cursor,
        .cursor_after = state.cursor,
        .previous_axis = previous_axis,
        .decision = decision,
        .controller_before = before_controller,
        .controller_after = next,
        .line_feedback = feedback,
    };
}

void absorb_symbol_b(WorkingStateB& state,
                     std::uint8_t symbol,
                     Domain domain,
                     std::size_t moves_per_symbol,
                     std::vector<MoveTraceB>* trace) {
    if (moves_per_symbol == 0U || moves_per_symbol > 255U) {
        throw std::invalid_argument("moves_per_symbol must be in [1,255]");
    }
    for (std::size_t phase = 0; phase < moves_per_symbol; ++phase) {
        auto move = apply_move_b(state, symbol, domain, static_cast<std::uint8_t>(phase));
        if (trace != nullptr) trace->push_back(std::move(move));
    }
    ++state.symbol_index;
}

void absorb_sequence_b(WorkingStateB& state,
                       std::span<const std::uint8_t> symbols,
                       Domain domain,
                       std::size_t moves_per_symbol,
                       std::vector<MoveTraceB>* trace) {
    for (const auto symbol : symbols) {
        absorb_symbol_b(state, symbol, domain, moves_per_symbol, trace);
    }
}

std::size_t controller_bit_distance_b(const ControllerStateB& left,
                                      const ControllerStateB& right) {
    std::size_t distance = static_cast<std::size_t>(std::popcount(left.path ^ right.path));
    for (std::size_t i = 0; i < 4U; ++i) {
        distance += static_cast<std::size_t>(std::popcount(left.lane[i] ^ right.lane[i]));
    }
    return distance;
}

std::uint64_t state_fingerprint_b(const WorkingStateB& state) {
    auto value = state.controller.path
               ^ (static_cast<std::uint64_t>(coordinate_word(state.cursor)) << 47U)
               ^ state.symbol_index;
    for (std::size_t i = 0; i < 4U; ++i) {
        value = rotl64(value ^ state.controller.lane[i], static_cast<unsigned>(9U + 11U * i))
              + static_cast<std::uint64_t>(state.controller.lane[i]) * 0x9E3779B185EBCA87ULL;
    }
    for (std::size_t i = 0; i < state.cube.storage().size(); ++i) {
        value = rotl64(value ^ state.cube.storage()[i] ^ static_cast<std::uint64_t>(i * 193U),
                       static_cast<unsigned>(1U + (i & 31U)))
              + static_cast<std::uint64_t>(state.cube.storage()[i]) * (263U + 2U * i);
    }
    return value;
}

} // namespace pvc1
