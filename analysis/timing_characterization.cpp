#include "pvc1/key_schedule.hpp"
#include "pvcaead0/aead.hpp"
#include "pvcmac0/mac.hpp"
#include "pvcrotsymenc1/symmetric_encryption.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#define DUDECT_IMPLEMENTATION
#include <dudect.h>

namespace {

constexpr std::size_t kAssociatedDataBytes = 32U;
constexpr std::size_t kPayloadBytes = 64U;
constexpr std::size_t kTagBytes = 32U;
constexpr std::size_t kStreamFrameBytes = 48U;
constexpr std::size_t kAuthContextBytes = 49U + kAssociatedDataBytes;
constexpr std::size_t kDefaultMeasurements = 12000U;
constexpr std::size_t kDefaultBatches = 3U;
constexpr std::uint64_t kDefaultSeed = UINT64_C(0x54494D494E473031);
constexpr std::uint64_t kMaximumPayloadCounter = (std::uint64_t{1U} << 59U) - 1U;
constexpr double kDudectThreshold = 10.0;

enum class Target : std::uint8_t {
    PositiveControl,
    C1Evaluate,
    M1Compute,
    M1VerifyMismatchPosition,
    Seal,
    OpenFailure,
    OpenSuccess,
    OpenValidityControl,
    C1KeyOnly,
    C1StreamFrameOnly,
};

struct Config {
    Target target = Target::PositiveControl;
    std::size_t measurements = kDefaultMeasurements;
    std::size_t batches = kDefaultBatches;
    std::uint64_t seed = kDefaultSeed;
};

struct TimingSample {
    pvcrotsymenc1::KeyPair512 keys{};
    pvcrotsymenc1::Nonce192 nonce{};
    std::array<std::uint8_t, kAssociatedDataBytes> associated_data{};
    std::array<std::uint8_t, kPayloadBytes> payload{};
    std::array<std::uint8_t, kStreamFrameBytes> stream_frame{};
    std::array<std::uint8_t, kAuthContextBytes> authentication_context{};
    std::array<std::uint8_t, kPayloadBytes> ciphertext{};
    std::array<std::uint8_t, kTagBytes> tag{};
};

static_assert(std::is_trivially_copyable_v<TimingSample>);
static_assert(alignof(TimingSample) == alignof(std::uint8_t));

struct RunState {
    Target target = Target::PositiveControl;
    std::uint64_t random_state = kDefaultSeed;
    std::size_t prepare_calls{};
};

struct TestSummary {
    bool enough_measurements{};
    std::size_t maximum_test_index{};
    double maximum_t{};
    double maximum_test_measurements{};
    double raw_t{};
    double raw_mean_class0{};
    double raw_mean_class1{};
    double raw_measurements_class0{};
    double raw_measurements_class1{};
};

RunState g_run;
volatile std::uint8_t g_sink{};

std::size_t parse_size(std::string_view text) {
    std::size_t value{};
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        throw std::invalid_argument("invalid integer: " + std::string(text));
    }
    return value;
}

std::uint64_t parse_u64(std::string_view text) {
    int base = 10;
    if (text.size() > 2U && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text.remove_prefix(2U);
        base = 16;
    }
    std::uint64_t value{};
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        throw std::invalid_argument("invalid u64: " + std::string(text));
    }
    return value;
}

Target parse_target(std::string_view name) {
    if (name == "positive-control") return Target::PositiveControl;
    if (name == "c1-evaluate") return Target::C1Evaluate;
    if (name == "c1-key-only") return Target::C1KeyOnly;
    if (name == "c1-streamframe-only") return Target::C1StreamFrameOnly;
    if (name == "m1-compute") return Target::M1Compute;
    if (name == "m1-verify-mismatch-position") return Target::M1VerifyMismatchPosition;
    if (name == "seal") return Target::Seal;
    if (name == "open-failure") return Target::OpenFailure;
    if (name == "open-success") return Target::OpenSuccess;
    if (name == "open-validity-control") return Target::OpenValidityControl;
    throw std::invalid_argument("unknown target: " + std::string(name));
}

std::string_view target_name(Target target) {
    switch (target) {
        case Target::PositiveControl: return "positive-control";
        case Target::C1Evaluate: return "c1-evaluate";
        case Target::C1KeyOnly: return "c1-key-only";
        case Target::C1StreamFrameOnly: return "c1-streamframe-only";
        case Target::M1Compute: return "m1-compute";
        case Target::M1VerifyMismatchPosition: return "m1-verify-mismatch-position";
        case Target::Seal: return "seal";
        case Target::OpenFailure: return "open-failure";
        case Target::OpenSuccess: return "open-success";
        case Target::OpenValidityControl: return "open-validity-control";
    }
    throw std::logic_error("unknown target");
}

std::pair<std::string_view, std::string_view> class_descriptions(Target target) {
    switch (target) {
        case Target::PositiveControl:
            return {"first-byte-nonzero", "last-byte-nonzero"};
        case Target::C1Evaluate:
            return {"fixed-key-and-streamframe", "random-key-and-streamframe"};
        case Target::C1KeyOnly:
            return {"fixed-key", "random-key"};
        case Target::C1StreamFrameOnly:
            return {"fixed-streamframe", "random-streamframe"};
        case Target::M1Compute:
            return {"fixed-key-context-message", "random-key-context-message"};
        case Target::M1VerifyMismatchPosition:
            return {"first-tag-byte-wrong", "last-tag-byte-wrong"};
        case Target::Seal:
            return {"fixed-seal-tuple", "random-seal-tuple"};
        case Target::OpenFailure:
            return {"fixed-invalid-open-tuple", "random-invalid-open-tuple"};
        case Target::OpenSuccess:
            return {"fixed-valid-open-tuple", "random-valid-open-tuple"};
        case Target::OpenValidityControl:
            return {"invalid-tag", "valid-tag"};
    }
    throw std::logic_error("unknown target");
}

Config parse_config(int argc, char** argv) {
    Config config;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        const auto next = [&](const char* name) {
            ++index;
            if (index >= argc) throw std::invalid_argument(std::string("missing ") + name);
            return std::string_view(argv[index]);
        };
        if (argument == "--target") {
            config.target = parse_target(next("target"));
        } else if (argument == "--measurements") {
            config.measurements = parse_size(next("measurements"));
        } else if (argument == "--batches") {
            config.batches = parse_size(next("batches"));
        } else if (argument == "--seed") {
            config.seed = parse_u64(next("seed"));
        } else {
            throw std::invalid_argument("unknown option: " + std::string(argument));
        }
    }
    if (config.measurements < 32U || (config.measurements % 2U) != 0U) {
        throw std::invalid_argument("measurements must be an even integer of at least 32");
    }
    if (config.batches == 0U) throw std::invalid_argument("batches must be positive");
    return config;
}

std::uint64_t splitmix64(std::uint64_t& state) {
    state += UINT64_C(0x9E3779B97F4A7C15);
    auto value = state;
    value = (value ^ (value >> 30U)) * UINT64_C(0xBF58476D1CE4E5B9);
    value = (value ^ (value >> 27U)) * UINT64_C(0x94D049BB133111EB);
    return value ^ (value >> 31U);
}

std::uint64_t target_domain(Target target) {
    switch (target) {
        case Target::PositiveControl: return UINT64_C(0xD0DEC70000000000);
        case Target::C1Evaluate: return UINT64_C(0xD0DEC70000000001);
        case Target::M1Compute: return UINT64_C(0xD0DEC70000000002);
        case Target::M1VerifyMismatchPosition: return UINT64_C(0xD0DEC70000000003);
        case Target::Seal: return UINT64_C(0xD0DEC70000000004);
        case Target::OpenFailure: return UINT64_C(0xD0DEC70000000005);
        case Target::OpenSuccess: return UINT64_C(0xD0DEC70000000006);
        case Target::OpenValidityControl: return UINT64_C(0xD0DEC70000000007);
        case Target::C1KeyOnly: return UINT64_C(0xD0DEC70000000008);
        case Target::C1StreamFrameOnly: return UINT64_C(0xD0DEC70000000009);
    }
    throw std::logic_error("unknown target");
}

template <std::size_t Size>
void fill_random(std::array<std::uint8_t, Size>& output, std::uint64_t& state) {
    std::uint64_t word{};
    for (std::size_t index = 0U; index < output.size(); ++index) {
        if ((index % 8U) == 0U) word = splitmix64(state);
        output[index] = static_cast<std::uint8_t>(word & UINT64_C(0xFF));
        word >>= 8U;
    }
}

template <std::size_t Size>
void copy_exact(std::array<std::uint8_t, Size>& destination,
                std::span<const std::uint8_t> source,
                const char* field) {
    if (source.size() != destination.size()) {
        throw std::logic_error(std::string("unexpected ") + field + " length");
    }
    std::copy(source.begin(), source.end(), destination.begin());
}

void randomize_base(TimingSample& sample, std::uint64_t& state) {
    fill_random(sample.keys.encryption_key, state);
    fill_random(sample.keys.authentication_key, state);
    fill_random(sample.nonce, state);
    fill_random(sample.associated_data, state);
    fill_random(sample.payload, state);
}

void prepare_stream_frame(TimingSample& sample, std::uint64_t counter) {
    const auto frame = pvcaead0::frame_stream_block(
        sample.nonce, counter, pvcaead0::TagSize::Bits256);
    copy_exact(sample.stream_frame, frame, "StreamFrame");
}

void prepare_authentication_context(TimingSample& sample) {
    const auto context = pvcaead0::frame_authentication_context(
        sample.nonce, sample.associated_data, pvcaead0::TagSize::Bits256);
    copy_exact(sample.authentication_context, context, "AuthContext");
}

void prepare_sealed_message(TimingSample& sample) {
    const auto sealed = pvcrotsymenc1::seal(
        sample.keys,
        sample.nonce,
        sample.associated_data,
        sample.payload,
        pvcrotsymenc1::TagSize::Bits256);
    copy_exact(sample.ciphertext, sealed.ciphertext, "ciphertext");
    copy_exact(sample.tag, sealed.tag, "tag");
}

TimingSample make_sample(Target target, std::uint8_t input_class, std::uint64_t& state) {
    TimingSample sample;
    const auto random_class = input_class == 1U;

    if (target == Target::PositiveControl) {
        const auto index = random_class ? sample.payload.size() - 1U : 0U;
        sample.payload[index] = 1U;
        return sample;
    }

    const auto randomize_complete_base = target == Target::C1Evaluate
        || target == Target::M1Compute
        || target == Target::Seal
        || target == Target::OpenFailure
        || target == Target::OpenSuccess;
    if (random_class && randomize_complete_base) {
        randomize_base(sample, state);
    } else if (random_class && target == Target::C1KeyOnly) {
        fill_random(sample.keys.encryption_key, state);
    } else if (random_class && target == Target::C1StreamFrameOnly) {
        fill_random(sample.nonce, state);
    }

    switch (target) {
        case Target::PositiveControl:
            break;
        case Target::C1Evaluate:
        case Target::C1StreamFrameOnly:
        case Target::C1KeyOnly: {
            const auto counter = random_class && target != Target::C1KeyOnly
                ? splitmix64(state) & kMaximumPayloadCounter
                : std::uint64_t{};
            prepare_stream_frame(sample, counter);
            break;
        }
        case Target::M1Compute:
            prepare_authentication_context(sample);
            break;
        case Target::M1VerifyMismatchPosition: {
            prepare_authentication_context(sample);
            const auto tag = pvcmac0::compute_tag(
                sample.keys.authentication_key,
                sample.authentication_context,
                sample.payload,
                pvcmac0::TagSize::Bits256);
            copy_exact(sample.tag, tag, "M1 tag");
            const auto index = random_class ? sample.tag.size() - 1U : 0U;
            sample.tag[index] ^= 1U;
            break;
        }
        case Target::Seal:
            break;
        case Target::OpenFailure:
            prepare_sealed_message(sample);
            sample.tag[0] ^= 1U;
            break;
        case Target::OpenSuccess:
            prepare_sealed_message(sample);
            break;
        case Target::OpenValidityControl:
            prepare_sealed_message(sample);
            if (!random_class) sample.tag[0] ^= 1U;
            break;
    }
    return sample;
}

std::vector<std::uint8_t> balanced_shuffled_classes(std::size_t count,
                                                    std::uint64_t& state) {
    std::vector<std::uint8_t> classes(count);
    std::fill(classes.begin() + static_cast<std::ptrdiff_t>(count / 2U),
              classes.end(), 1U);
    for (std::size_t index = count; index > 1U; --index) {
        const auto other = static_cast<std::size_t>(
            splitmix64(state) % static_cast<std::uint64_t>(index));
        std::swap(classes[index - 1U], classes[other]);
    }
    return classes;
}

std::uint8_t positive_control(const TimingSample& sample) {
    const volatile std::uint8_t* values = sample.payload.data();
    for (std::size_t index = 0U; index < sample.payload.size(); ++index) {
        if (values[index] != 0U) return static_cast<std::uint8_t>(index);
    }
    return 0U;
}

std::uint8_t evaluate_sample(const TimingSample& sample) {
    switch (g_run.target) {
        case Target::PositiveControl:
            return positive_control(sample);
        case Target::C1Evaluate:
        case Target::C1KeyOnly:
        case Target::C1StreamFrameOnly: {
            const auto output = pvc1::research_keyed_return_output_a2(
                sample.keys.encryption_key, sample.stream_frame);
            return output[0];
        }
        case Target::M1Compute: {
            const auto tag = pvcmac0::compute_tag(
                sample.keys.authentication_key,
                sample.authentication_context,
                sample.payload,
                pvcmac0::TagSize::Bits256);
            return tag[0];
        }
        case Target::M1VerifyMismatchPosition:
            return pvcmac0::verify_tag(
                sample.keys.authentication_key,
                sample.authentication_context,
                sample.payload,
                sample.tag) ? 1U : 0U;
        case Target::Seal: {
            const auto sealed = pvcrotsymenc1::seal(
                sample.keys,
                sample.nonce,
                sample.associated_data,
                sample.payload,
                pvcrotsymenc1::TagSize::Bits256);
            return static_cast<std::uint8_t>(sealed.ciphertext[0] ^ sealed.tag[0]);
        }
        case Target::OpenFailure:
        case Target::OpenSuccess:
        case Target::OpenValidityControl: {
            const auto opened = pvcrotsymenc1::open(
                sample.keys,
                sample.nonce,
                sample.associated_data,
                sample.ciphertext,
                sample.tag);
            return opened.has_value() ? opened->front() : 0U;
        }
    }
    return 0U;
}

double welch_t(const ttest_ctx_t& test) {
    if (test.n[0] < 2.0 || test.n[1] < 2.0) return 0.0;
    const auto variance0 = test.m2[0] / (test.n[0] - 1.0);
    const auto variance1 = test.m2[1] / (test.n[1] - 1.0);
    const auto denominator = std::sqrt(variance0 / test.n[0] + variance1 / test.n[1]);
    if (denominator == 0.0) return 0.0;
    return (test.mean[0] - test.mean[1]) / denominator;
}

TestSummary summarize(const dudect_ctx_t& context) {
    TestSummary summary;
    const auto& raw = *context.ttest_ctxs[0];
    summary.raw_t = welch_t(raw);
    summary.raw_mean_class0 = raw.mean[0];
    summary.raw_mean_class1 = raw.mean[1];
    summary.raw_measurements_class0 = raw.n[0];
    summary.raw_measurements_class1 = raw.n[1];

    for (std::size_t index = 0U; index < DUDECT_TESTS; ++index) {
        const auto& test = *context.ttest_ctxs[index];
        if (test.n[0] <= static_cast<double>(DUDECT_ENOUGH_MEASUREMENTS)
            || test.n[1] <= static_cast<double>(DUDECT_ENOUGH_MEASUREMENTS)) {
            continue;
        }
        summary.enough_measurements = true;
        const auto candidate = welch_t(test);
        if (std::abs(candidate) > std::abs(summary.maximum_t)) {
            summary.maximum_t = candidate;
            summary.maximum_test_index = index;
            summary.maximum_test_measurements = test.n[0] + test.n[1];
        }
    }
    return summary;
}

std::string test_name(std::size_t index) {
    if (index == 0U) return "raw-first-order";
    if (index == DUDECT_TESTS - 1U) return "second-order";
    return "cropped-" + std::to_string(index);
}

std::string_view compiler_name() {
#if defined(__clang__)
    return "clang-" __clang_version__;
#elif defined(__GNUC__)
    return "gcc-" __VERSION__;
#else
    return "unknown";
#endif
}

} // namespace

extern "C" void prepare_inputs(dudect_config_t* config,
                               std::uint8_t* input_data,
                               std::uint8_t* classes) {
    try {
        if (config->chunk_size != sizeof(TimingSample)) {
            throw std::logic_error("dudect chunk size mismatch");
        }
        auto shuffled = balanced_shuffled_classes(
            config->number_measurements, g_run.random_state);
        for (std::size_t index = 0U; index < config->number_measurements; ++index) {
            classes[index] = shuffled[index];
            const auto sample = make_sample(
                g_run.target, shuffled[index], g_run.random_state);
            std::memcpy(input_data + index * config->chunk_size,
                        &sample,
                        sizeof(sample));
        }
        ++g_run.prepare_calls;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "prepare_inputs error: %s\n", error.what());
        std::abort();
    }
}

extern "C" std::uint8_t do_one_computation(std::uint8_t* data) {
    TimingSample sample;
    std::memcpy(&sample, data, sizeof(sample));
    const auto result = evaluate_sample(sample);
    g_sink = static_cast<std::uint8_t>(g_sink ^ result);
    return result;
}

int main(int argc, char** argv) {
    try {
        const auto config = parse_config(argc, argv);
        g_run.target = config.target;
        g_run.random_state = config.seed ^ target_domain(config.target);
        const auto [class0, class1] = class_descriptions(config.target);

        std::printf("PVC-RotSymEnc-1 timing characterization\n");
        std::printf("campaign_version=1\n");
        std::printf("construction_version=0.1.0-draft\n");
        std::printf("dudect_commit=dc269651fb2567e46755cfb2a13d3875592968b5\n");
        std::printf("compiler=%s\n", std::string(compiler_name()).c_str());
        std::printf("target=%s\n", std::string(target_name(config.target)).c_str());
        std::printf("class0=%s\n", std::string(class0).c_str());
        std::printf("class1=%s\n", std::string(class1).c_str());
        std::printf("seed=0x%016llX\n", static_cast<unsigned long long>(config.seed));
        std::printf("measurements_per_batch=%zu\n", config.measurements);
        std::printf("warmup_batches=1\n");
        std::printf("statistics_batches=%zu\n", config.batches);
        std::printf("tag_bits=256\nassociated_data_bytes=%zu\npayload_bytes=%zu\n",
                    kAssociatedDataBytes,
                    kPayloadBytes);

        dudect_config_t dudect_config{};
        dudect_config.chunk_size = sizeof(TimingSample);
        dudect_config.number_measurements = config.measurements;
        dudect_ctx_t context{};
        if (dudect_init(&context, &dudect_config) != 0) {
            throw std::runtime_error("dudect_init failed");
        }

        for (std::size_t batch = 0U; batch <= config.batches; ++batch) {
            std::printf("batch=%zu phase=%s\n", batch,
                        batch == 0U ? "warmup" : "statistics");
            (void)dudect_main(&context);
        }

        const auto summary = summarize(context);
        const auto leakage = summary.enough_measurements
            && std::abs(summary.maximum_t) > kDudectThreshold;
        std::printf("summary target=%s raw_t=%.6f raw_mean_class0=%.6f "
                    "raw_mean_class1=%.6f raw_n_class0=%.0f raw_n_class1=%.0f "
                    "max_t=%.6f max_test=%s max_test_measurements=%.0f "
                    "threshold=%.1f enough_measurements=%u leakage_evidence=%u sink=%u\n",
                    std::string(target_name(config.target)).c_str(),
                    summary.raw_t,
                    summary.raw_mean_class0,
                    summary.raw_mean_class1,
                    summary.raw_measurements_class0,
                    summary.raw_measurements_class1,
                    summary.maximum_t,
                    test_name(summary.maximum_test_index).c_str(),
                    summary.maximum_test_measurements,
                    kDudectThreshold,
                    summary.enough_measurements ? 1U : 0U,
                    leakage ? 1U : 0U,
                    static_cast<unsigned>(g_sink));
        std::printf("interpretation=leakage-detection-not-a-constant-time-proof-or-attack\n");
        (void)dudect_free(&context);
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "error: %s\n", error.what());
        return 1;
    }
}
