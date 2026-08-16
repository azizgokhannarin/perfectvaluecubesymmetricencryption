#include "pvcrotsymenc1/symmetric_encryption.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#if defined(__APPLE__) || defined(__linux__) || defined(__unix__)
#include <sys/resource.h>
#endif

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#include <intrin.h>
#elif defined(__i386__) || defined(__x86_64__)
#include <x86intrin.h>
#endif

namespace {

constexpr std::size_t kAssociatedDataBytes = 32U;
constexpr std::size_t kDefaultSamples = 5U;
constexpr std::uint64_t kDefaultTargetNanoseconds = UINT64_C(100000000);
constexpr std::size_t kDefaultMaximumIterations = 1U << 20U;
constexpr std::uint64_t kSeed = UINT64_C(0x50455246424D4B31);
constexpr double kBytesPerMebibyte = 1024.0 * 1024.0;

enum class Operation : std::uint8_t {
    Seal,
    Open,
};

struct Config {
    Operation operation = Operation::Seal;
    pvcrotsymenc1::TagSize tag_size = pvcrotsymenc1::TagSize::Bits256;
    std::size_t message_size = 64U;
    std::size_t samples = kDefaultSamples;
    std::uint64_t target_nanoseconds = kDefaultTargetNanoseconds;
    std::size_t maximum_iterations = kDefaultMaximumIterations;
};

struct Fixture {
    pvcrotsymenc1::KeyPair512 keys{};
    pvcrotsymenc1::Nonce192 nonce{};
    std::array<std::uint8_t, kAssociatedDataBytes> associated_data{};
    std::vector<std::uint8_t> plaintext;
    pvcrotsymenc1::SealedMessage sealed;
};

struct TscStamp {
    std::uint64_t ticks{};
    unsigned auxiliary{};
};

struct Sample {
    std::uint64_t elapsed_nanoseconds{};
    std::optional<std::uint64_t> tsc_ticks;
};

volatile std::uint64_t g_sink{};

std::size_t parse_size(std::string_view text) {
    std::size_t value{};
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        throw std::invalid_argument("invalid integer: " + std::string(text));
    }
    return value;
}

std::uint64_t parse_u64(std::string_view text) {
    std::uint64_t value{};
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        throw std::invalid_argument("invalid integer: " + std::string(text));
    }
    return value;
}

Operation parse_operation(std::string_view text) {
    if (text == "seal") return Operation::Seal;
    if (text == "open") return Operation::Open;
    throw std::invalid_argument("operation must be seal or open");
}

pvcrotsymenc1::TagSize parse_tag_size(std::string_view text) {
    if (text == "128") return pvcrotsymenc1::TagSize::Bits128;
    if (text == "192") return pvcrotsymenc1::TagSize::Bits192;
    if (text == "256") return pvcrotsymenc1::TagSize::Bits256;
    throw std::invalid_argument("tag-bits must be 128, 192, or 256");
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

        if (argument == "--operation") {
            config.operation = parse_operation(next("operation"));
        } else if (argument == "--tag-bits") {
            config.tag_size = parse_tag_size(next("tag-bits"));
        } else if (argument == "--size") {
            config.message_size = parse_size(next("size"));
        } else if (argument == "--samples") {
            config.samples = parse_size(next("samples"));
        } else if (argument == "--target-ms") {
            const auto milliseconds = parse_u64(next("target-ms"));
            if (milliseconds > std::numeric_limits<std::uint64_t>::max() / UINT64_C(1000000)) {
                throw std::invalid_argument("target-ms is too large");
            }
            config.target_nanoseconds = milliseconds * UINT64_C(1000000);
        } else if (argument == "--max-iterations") {
            config.maximum_iterations = parse_size(next("max-iterations"));
        } else {
            throw std::invalid_argument("unknown option: " + std::string(argument));
        }
    }

    if (config.samples == 0U || config.samples > 101U) {
        throw std::invalid_argument("samples must be in [1, 101]");
    }
    if (config.target_nanoseconds == 0U) {
        throw std::invalid_argument("target-ms must be positive");
    }
    if (config.maximum_iterations == 0U) {
        throw std::invalid_argument("max-iterations must be positive");
    }
    return config;
}

std::uint64_t splitmix64(std::uint64_t& state) {
    state += UINT64_C(0x9E3779B97F4A7C15);
    auto value = state;
    value = (value ^ (value >> 30U)) * UINT64_C(0xBF58476D1CE4E5B9);
    value = (value ^ (value >> 27U)) * UINT64_C(0x94D049BB133111EB);
    return value ^ (value >> 31U);
}

void fill_bytes(std::span<std::uint8_t> output, std::uint64_t& state) {
    std::uint64_t word{};
    for (std::size_t index = 0U; index < output.size(); ++index) {
        if ((index % 8U) == 0U) word = splitmix64(state);
        output[index] = static_cast<std::uint8_t>(word & UINT64_C(0xFF));
        word >>= 8U;
    }
}

Fixture make_fixture(const Config& config) {
    Fixture fixture;
    fixture.plaintext.resize(config.message_size);
    auto state = kSeed;
    fill_bytes(fixture.keys.encryption_key, state);
    fill_bytes(fixture.keys.authentication_key, state);
    fill_bytes(fixture.nonce, state);
    fill_bytes(fixture.associated_data, state);
    fill_bytes(fixture.plaintext, state);

    if (config.operation == Operation::Open) {
        fixture.sealed = pvcrotsymenc1::seal(
            fixture.keys,
            fixture.nonce,
            fixture.associated_data,
            fixture.plaintext,
            config.tag_size);
    }
    return fixture;
}

constexpr bool has_tsc() noexcept {
#if (defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))) \
    || defined(__i386__) || defined(__x86_64__)
    return true;
#else
    return false;
#endif
}

TscStamp read_tsc() noexcept {
#if (defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))) \
    || defined(__i386__) || defined(__x86_64__)
    unsigned auxiliary{};
    _mm_lfence();
    const auto ticks = __rdtscp(&auxiliary);
    _mm_lfence();
    return TscStamp{ticks, auxiliary};
#else
    return {};
#endif
}

std::optional<std::uint64_t> peak_rss_kib() noexcept {
#if defined(__APPLE__) || defined(__linux__) || defined(__unix__)
    rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage) != 0 || usage.ru_maxrss < 0) {
        return std::nullopt;
    }
    const auto raw = static_cast<std::uint64_t>(usage.ru_maxrss);
#if defined(__APPLE__)
    return raw / UINT64_C(1024);
#else
    return raw;
#endif
#else
    return std::nullopt;
#endif
}

std::uint64_t consume(std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.empty()) return 0U;
    return static_cast<std::uint64_t>(bytes.front())
        ^ (static_cast<std::uint64_t>(bytes.back()) << 8U)
        ^ (static_cast<std::uint64_t>(bytes.size()) << 16U);
}

Sample run_batch(const Config& config, const Fixture& fixture, std::size_t iterations) {
    using Clock = std::chrono::steady_clock;

    std::uint64_t sink{};
    const auto time_begin = Clock::now();
    const auto tsc_begin = read_tsc();
    for (std::size_t iteration = 0U; iteration < iterations; ++iteration) {
        if (config.operation == Operation::Seal) {
            const auto sealed = pvcrotsymenc1::seal(
                fixture.keys,
                fixture.nonce,
                fixture.associated_data,
                fixture.plaintext,
                config.tag_size);
            if (sealed.ciphertext.size() != fixture.plaintext.size()
                || sealed.tag.size() != pvcrotsymenc1::tag_size_bytes(config.tag_size)) {
                throw std::runtime_error("seal returned an unexpected length during benchmark");
            }
            sink ^= consume(sealed.ciphertext);
            sink ^= consume(sealed.tag) + static_cast<std::uint64_t>(iteration);
        } else {
            const auto opened = pvcrotsymenc1::open(
                fixture.keys,
                fixture.nonce,
                fixture.associated_data,
                fixture.sealed.ciphertext,
                fixture.sealed.tag);
            if (!opened.has_value() || *opened != fixture.plaintext) {
                throw std::runtime_error("valid open self-check failed during benchmark");
            }
            sink ^= consume(*opened) + static_cast<std::uint64_t>(iteration);
        }
    }
    const auto tsc_end = read_tsc();
    const auto time_end = Clock::now();
    g_sink = sink;

    const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
        time_end - time_begin).count();
    if (elapsed <= 0) throw std::runtime_error("non-positive benchmark duration");

    std::optional<std::uint64_t> ticks;
    if (has_tsc()) {
        if (tsc_begin.auxiliary != tsc_end.auxiliary) {
            throw std::runtime_error("CPU migration detected; run the benchmark pinned to one CPU");
        }
        if (tsc_end.ticks < tsc_begin.ticks) {
            throw std::runtime_error("TSC moved backwards");
        }
        ticks = tsc_end.ticks - tsc_begin.ticks;
    }
    return Sample{static_cast<std::uint64_t>(elapsed), ticks};
}

std::size_t calibrated_iterations(const Config& config, const Fixture& fixture) {
    std::size_t iterations = 1U;
    for (;;) {
        const auto sample = run_batch(config, fixture, iterations);
        if (sample.elapsed_nanoseconds >= config.target_nanoseconds
            || iterations >= config.maximum_iterations) {
            return iterations;
        }

        const auto ratio = static_cast<double>(config.target_nanoseconds)
            / static_cast<double>(sample.elapsed_nanoseconds);
        const auto rounded = static_cast<std::size_t>(std::ceil(ratio));
        const auto multiplier = std::clamp(rounded, std::size_t{2U}, std::size_t{16U});
        if (iterations > config.maximum_iterations / multiplier) {
            return config.maximum_iterations;
        }
        iterations *= multiplier;
    }
}

double median(std::vector<std::uint64_t> values) {
    if (values.empty()) throw std::logic_error("median requires samples");
    std::sort(values.begin(), values.end());
    const auto middle = values.size() / 2U;
    if ((values.size() % 2U) != 0U) return static_cast<double>(values[middle]);
    return static_cast<double>(values[middle - 1U]) / 2.0
        + static_cast<double>(values[middle]) / 2.0;
}

std::string_view operation_name(Operation operation) noexcept {
    return operation == Operation::Seal ? "seal" : "open-success";
}

unsigned tag_bits(pvcrotsymenc1::TagSize size) noexcept {
    return static_cast<unsigned>(pvcrotsymenc1::tag_size_bytes(size) * 8U);
}

std::string_view compiler_id() noexcept {
#if defined(__clang__)
    return "clang";
#elif defined(__GNUC__)
    return "gcc";
#elif defined(_MSC_VER)
    return "msvc";
#else
    return "unknown";
#endif
}

std::string compiler_version() {
#if defined(__clang__)
    return __clang_version__;
#elif defined(__GNUC__)
    return __VERSION__;
#elif defined(_MSC_VER)
    return std::to_string(_MSC_VER);
#else
    return "unknown";
#endif
}

std::string_view architecture_name() noexcept {
#if defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    return "aarch64";
#elif defined(__i386__) || defined(_M_IX86)
    return "x86";
#else
    return "unknown";
#endif
}

void print_json_string(std::ostream& output, std::string_view text) {
    output << '"';
    for (const char character : text) {
        switch (character) {
            case '"': output << "\\\""; break;
            case '\\': output << "\\\\"; break;
            case '\n': output << "\\n"; break;
            case '\r': output << "\\r"; break;
            case '\t': output << "\\t"; break;
            default: output << character; break;
        }
    }
    output << '"';
}

void print_optional_u64(const std::optional<std::uint64_t>& value) {
    if (value.has_value()) {
        std::cout << *value;
    } else {
        std::cout << "null";
    }
}

void print_u64_array(const std::vector<std::uint64_t>& values) {
    std::cout << '[';
    for (std::size_t index = 0U; index < values.size(); ++index) {
        if (index != 0U) std::cout << ',';
        std::cout << values[index];
    }
    std::cout << ']';
}

void report(const Config& config,
            std::size_t iterations,
            const std::vector<Sample>& samples,
            const std::optional<std::uint64_t>& peak_rss_before,
            const std::optional<std::uint64_t>& peak_rss_after) {
    std::vector<std::uint64_t> elapsed_values;
    std::vector<std::uint64_t> tick_values;
    elapsed_values.reserve(samples.size());
    tick_values.reserve(samples.size());
    for (const auto& sample : samples) {
        elapsed_values.push_back(sample.elapsed_nanoseconds);
        if (sample.tsc_ticks.has_value()) tick_values.push_back(*sample.tsc_ticks);
    }

    const auto median_elapsed = median(elapsed_values);
    const auto latency_nanoseconds = median_elapsed / static_cast<double>(iterations);
    const auto median_ticks = tick_values.empty()
        ? std::optional<double>{}
        : std::optional<double>{median(tick_values)};
    const auto ticks_per_operation = median_ticks.has_value()
        ? std::optional<double>{*median_ticks / static_cast<double>(iterations)}
        : std::optional<double>{};
    const auto ticks_per_byte = ticks_per_operation.has_value() && config.message_size != 0U
        ? std::optional<double>{*ticks_per_operation / static_cast<double>(config.message_size)}
        : std::optional<double>{};
    const auto mebibytes_per_second = config.message_size == 0U
        ? std::optional<double>{}
        : std::optional<double>{
            (static_cast<double>(config.message_size) * static_cast<double>(iterations)
             / kBytesPerMebibyte)
            / (median_elapsed / 1.0e9)};

    const auto tag_bytes = pvcrotsymenc1::tag_size_bytes(config.tag_size);
    const auto input_bytes = config.operation == Operation::Seal
        ? kAssociatedDataBytes + config.message_size
        : kAssociatedDataBytes + config.message_size + tag_bytes;
    const auto output_bytes = config.operation == Operation::Seal
        ? config.message_size + tag_bytes
        : config.message_size;

    std::cout << std::setprecision(17);
    std::cout << '{';
    std::cout << "\"benchmark_version\":1";
    std::cout << ",\"construction_version\":\"0.1.0-draft\"";
    std::cout << ",\"operation\":";
    print_json_string(std::cout, operation_name(config.operation));
    std::cout << ",\"message_bytes\":" << config.message_size;
    std::cout << ",\"associated_data_bytes\":" << kAssociatedDataBytes;
    std::cout << ",\"tag_bits\":" << tag_bits(config.tag_size);
    std::cout << ",\"seed\":\"0x50455246424D4B31\"";
    std::cout << ",\"compiler_id\":";
    print_json_string(std::cout, compiler_id());
    std::cout << ",\"compiler_version\":";
    print_json_string(std::cout, compiler_version());
    std::cout << ",\"architecture\":";
    print_json_string(std::cout, architecture_name());
#if defined(NDEBUG)
    std::cout << ",\"ndebug\":true";
#else
    std::cout << ",\"ndebug\":false";
#endif
    std::cout << ",\"iterations_per_sample\":" << iterations;
    std::cout << ",\"samples\":" << samples.size();
    std::cout << ",\"target_sample_nanoseconds\":" << config.target_nanoseconds;
    std::cout << ",\"latency_nanoseconds_median\":" << latency_nanoseconds;
    std::cout << ",\"mebibytes_per_second_median\":";
    if (mebibytes_per_second.has_value()) std::cout << *mebibytes_per_second;
    else std::cout << "null";
    std::cout << ",\"tsc_available\":" << (has_tsc() ? "true" : "false");
    std::cout << ",\"tsc_ticks_per_operation_median\":";
    if (ticks_per_operation.has_value()) std::cout << *ticks_per_operation;
    else std::cout << "null";
    std::cout << ",\"tsc_ticks_per_byte_median\":";
    if (ticks_per_byte.has_value()) std::cout << *ticks_per_byte;
    else std::cout << "null";
    std::cout << ",\"api_input_bytes\":" << input_bytes;
    std::cout << ",\"api_output_bytes\":" << output_bytes;
    std::cout << ",\"peak_rss_before_measurement_kib\":";
    print_optional_u64(peak_rss_before);
    std::cout << ",\"peak_rss_after_measurement_kib\":";
    print_optional_u64(peak_rss_after);
    std::cout << ",\"elapsed_nanoseconds_samples\":";
    print_u64_array(elapsed_values);
    std::cout << ",\"tsc_tick_samples\":";
    print_u64_array(tick_values);
    std::cout << ",\"sink\":" << g_sink;
    std::cout << "}\n";
}

} // namespace

int main(int argc, char** argv) {
    try {
        const auto config = parse_config(argc, argv);
        const auto fixture = make_fixture(config);
        const auto peak_before = peak_rss_kib();
        const auto iterations = calibrated_iterations(config, fixture);

        std::vector<Sample> samples;
        samples.reserve(config.samples);
        for (std::size_t sample = 0U; sample < config.samples; ++sample) {
            samples.push_back(run_batch(config, fixture, iterations));
        }
        const auto peak_after = peak_rss_kib();
        report(config, iterations, samples, peak_before, peak_after);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
