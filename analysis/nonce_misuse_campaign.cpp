#include "nonce_management/nonce_management.hpp"
#include "pvcrotsymenc1/symmetric_encryption.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

using pvcrotsymenc1::Key256;
using pvcrotsymenc1::KeyPair512;
using pvcrotsymenc1::Nonce192;
using pvcrotsymenc1::research::NonceObservation;
using pvcrotsymenc1::research::NonceReuseDetector;
using pvcrotsymenc1::research::NonceScope128;
using pvcrotsymenc1::research::PersistencePoint;
using pvcrotsymenc1::research::PersistentNonceCounter;

constexpr std::uint64_t kSeed = UINT64_C(0x4E4F4E43454D4754);
constexpr std::size_t kFullWidthSamples = 65536U;
constexpr std::size_t kReducedTrials = 256U;
constexpr std::size_t kReducedSamples = 4096U;
constexpr std::size_t kWorkers = 8U;
constexpr std::size_t kAllocationsPerWorker = 128U;

PersistencePoint gCrashPoint = PersistencePoint::AfterLock;

[[noreturn]] void fail(const std::string& message) {
    throw std::runtime_error(message);
}

void require(bool condition, const std::string& message) {
    if (!condition) fail(message);
}

std::uint64_t next_random(std::uint64_t& state) noexcept {
    state += UINT64_C(0x9E3779B97F4A7C15);
    auto value = state;
    value = (value ^ (value >> 30U)) * UINT64_C(0xBF58476D1CE4E5B9);
    value = (value ^ (value >> 27U)) * UINT64_C(0x94D049BB133111EB);
    return value ^ (value >> 31U);
}

Nonce192 random_nonce(std::uint64_t& state) {
    Nonce192 nonce{};
    for (std::size_t word = 0U; word < 3U; ++word) {
        const auto value = next_random(state);
        for (std::size_t byte = 0U; byte < 8U; ++byte) {
            const auto shift = static_cast<unsigned>((7U - byte) * 8U);
            nonce[word * 8U + byte] =
                static_cast<std::uint8_t>((value >> shift) & UINT64_C(0xFF));
        }
    }
    return nonce;
}

Nonce192 nonce_from_counter(std::uint64_t value) {
    Nonce192 nonce{};
    for (std::size_t index = 0U; index < 8U; ++index) {
        nonce[nonce.size() - 1U - index] =
            static_cast<std::uint8_t>((value >> (index * 8U)) & UINT64_C(0xFF));
    }
    return nonce;
}

Key256 key_with_offset(std::uint8_t offset) {
    Key256 key{};
    for (std::size_t index = 0U; index < key.size(); ++index) {
        key[index] = static_cast<std::uint8_t>(offset + static_cast<std::uint8_t>(index));
    }
    return key;
}

NonceScope128 scope_with_offset(std::uint8_t offset) {
    NonceScope128 scope{};
    for (std::size_t index = 0U; index < scope.size(); ++index) {
        scope[index] = static_cast<std::uint8_t>(offset + static_cast<std::uint8_t>(index));
    }
    return scope;
}

void crash_hook(PersistencePoint point) {
    if (point == gCrashPoint) {
        ::_exit(80 + static_cast<int>(point));
    }
}

void wait_for_expected_exit(pid_t process, int expected) {
    int status = 0;
    if (::waitpid(process, &status, 0) != process) fail("waitpid failed");
    require(WIFEXITED(status), "child did not exit normally");
    require(WEXITSTATUS(status) == expected, "child exit status mismatch");
}

struct TemporaryDirectory {
    std::filesystem::path path;

    explicit TemporaryDirectory(std::filesystem::path value)
        : path(std::move(value)) {}

    TemporaryDirectory(const TemporaryDirectory&) = delete;
    TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

    TemporaryDirectory(TemporaryDirectory&& other) noexcept
        : path(std::move(other.path)) {
        other.path.clear();
    }

    TemporaryDirectory& operator=(TemporaryDirectory&&) = delete;

    ~TemporaryDirectory() {
        if (path.empty()) return;
        std::error_code error;
        (void)std::filesystem::remove_all(path, error);
    }
};

TemporaryDirectory make_temporary_directory() {
    const auto name = std::string("pvc-rotsymenc1-nonce-")
        + std::to_string(static_cast<long long>(::getpid()));
    TemporaryDirectory directory{std::filesystem::temp_directory_path() / name};
    if (std::filesystem::exists(directory.path)) {
        fail("nonce campaign temporary directory already exists");
    }
    std::filesystem::create_directory(directory.path);
    return directory;
}

void test_reuse_detector_and_xor() {
    NonceReuseDetector detector;
    const auto first_key = key_with_offset(UINT8_C(0x10));
    const auto second_key = key_with_offset(UINT8_C(0x90));
    const auto nonce = nonce_from_counter(UINT64_C(7));
    require(detector.observe(first_key, nonce) == NonceObservation::Fresh,
            "first nonce observation was not fresh");
    require(detector.observe(first_key, nonce) == NonceObservation::Reused,
            "same-key nonce reuse was not detected");
    require(detector.observe(second_key, nonce) == NonceObservation::Fresh,
            "different-key nonce was incorrectly rejected");
    require(detector.observations() == 2U, "reuse detector observation count mismatch");

    KeyPair512 keys{first_key, key_with_offset(UINT8_C(0x50))};
    std::vector<std::uint8_t> first_plaintext(96U);
    std::vector<std::uint8_t> second_plaintext(96U);
    for (std::size_t index = 0U; index < first_plaintext.size(); ++index) {
        first_plaintext[index] = static_cast<std::uint8_t>(index);
        second_plaintext[index] = static_cast<std::uint8_t>(UINT8_C(0xF0)
            ^ static_cast<std::uint8_t>(index));
    }
    const std::array<std::uint8_t, 3> first_ad{1U, 2U, 3U};
    const std::array<std::uint8_t, 4> second_ad{4U, 5U, 6U, 7U};
    const auto first = pvcrotsymenc1::seal(
        keys, nonce, first_ad, first_plaintext, pvcrotsymenc1::TagSize::Bits256);
    const auto second = pvcrotsymenc1::seal(
        keys, nonce, second_ad, second_plaintext, pvcrotsymenc1::TagSize::Bits256);
    require(first.ciphertext.size() == second.ciphertext.size(),
            "nonce reuse ciphertext length mismatch");
    for (std::size_t index = 0U; index < first.ciphertext.size(); ++index) {
        require(static_cast<std::uint8_t>(
                    first.ciphertext[index] ^ second.ciphertext[index])
                    == static_cast<std::uint8_t>(
                        first_plaintext[index] ^ second_plaintext[index]),
                "nonce reuse XOR relation missing");
    }
    require(pvcrotsymenc1::open(
                keys, nonce, first_ad, first.ciphertext, first.tag).has_value(),
            "first reused-nonce message did not authenticate");
    require(pvcrotsymenc1::open(
                keys, nonce, second_ad, second.ciphertext, second.tag).has_value(),
            "second reused-nonce message did not authenticate");

    std::cout << "reuse-detector same_key_reuse=1 different_key_allowed=1 "
                 "tag_profile_independent_policy=1\n";
    std::cout << "nonce-reuse-xor bytes=96 relation_reproduced=1 "
                 "authentication_repairs_confidentiality=0\n";
}

void run_collision_simulation() {
    std::uint64_t state = kSeed;
    std::set<Nonce192> full_width;
    std::size_t full_collisions = 0U;
    for (std::size_t index = 0U; index < kFullWidthSamples; ++index) {
        if (!full_width.insert(random_nonce(state)).second) ++full_collisions;
    }
    require(full_collisions == 0U, "unexpected deterministic 192-bit sample collision");

    std::size_t reduced_collisions = 0U;
    for (std::size_t trial = 0U; trial < kReducedTrials; ++trial) {
        std::set<std::uint32_t> observed;
        for (std::size_t index = 0U; index < kReducedSamples; ++index) {
            const auto value = static_cast<std::uint32_t>(
                next_random(state) & UINT64_C(0xFFFFFF));
            if (!observed.insert(value).second) ++reduced_collisions;
        }
    }
    require(reduced_collisions > 0U, "reduced-width collision control found no collision");

    const auto full_expected =
        (static_cast<long double>(kFullWidthSamples)
         * static_cast<long double>(kFullWidthSamples - 1U))
        / std::ldexp(1.0L, 193);
    const auto reduced_expected =
        static_cast<long double>(kReducedTrials)
        * static_cast<long double>(kReducedSamples)
        * static_cast<long double>(kReducedSamples - 1U)
        / std::ldexp(1.0L, 25);
    const auto q64_probability =
        (std::ldexp(1.0L, 64) * (std::ldexp(1.0L, 64) - 1.0L))
        / std::ldexp(1.0L, 193);

    std::cout << std::scientific << std::setprecision(6)
              << "random-collision width=192 samples=" << kFullWidthSamples
              << " collisions=" << full_collisions
              << " birthday_expectation=" << full_expected << '\n'
              << "random-collision-control width=24 trials=" << kReducedTrials
              << " samples_per_trial=" << kReducedSamples
              << " collisions=" << reduced_collisions
              << " birthday_expectation=" << reduced_expected << '\n'
              << "random-collision-estimate width=192 q=2^64 probability_approx="
              << q64_probability << '\n'
              << std::defaultfloat;
}

void test_restart_and_scope(const std::filesystem::path& root) {
    const auto path = root / "restart.state";
    const auto scope = scope_with_offset(UINT8_C(0x20));
    for (std::uint64_t value = 0U; value < UINT64_C(256); ++value) {
        require(PersistentNonceCounter::allocate(path, scope) == nonce_from_counter(value),
                "persistent restart sequence mismatch");
    }
    bool scope_rejected = false;
    try {
        (void)PersistentNonceCounter::allocate(
            path, scope_with_offset(UINT8_C(0x40)));
    } catch (const std::invalid_argument&) {
        scope_rejected = true;
    }
    require(scope_rejected, "persistent counter accepted a different scope");
    require(PersistentNonceCounter::allocate(path, scope)
                == nonce_from_counter(UINT64_C(256)),
            "scope rejection changed persistent counter state");
    std::cout << "persistent-restart allocations=257 unique=257 scope_mismatch_rejected=1\n";
}

void test_crash_points(const std::filesystem::path& root) {
    const std::array<PersistencePoint, 4> points{
        PersistencePoint::AfterLock,
        PersistencePoint::AfterTemporarySync,
        PersistencePoint::AfterReplace,
        PersistencePoint::AfterDirectorySync,
    };
    std::size_t preserved = 0U;
    std::size_t skipped = 0U;
    for (const auto point : points) {
        const auto path = root / ("crash-" + std::to_string(static_cast<unsigned>(point))
                                  + ".state");
        const auto scope = scope_with_offset(
            static_cast<std::uint8_t>(UINT8_C(0x50)
                                      + static_cast<std::uint8_t>(point)));
        require(PersistentNonceCounter::allocate(path, scope) == nonce_from_counter(0U),
                "crash test initial allocation mismatch");
        const auto child = ::fork();
        if (child < 0) fail("fork failed in crash test");
        if (child == 0) {
            gCrashPoint = point;
            try {
                (void)PersistentNonceCounter::allocate(path, scope, crash_hook);
            } catch (...) {
                ::_exit(125);
            }
            ::_exit(126);
        }
        wait_for_expected_exit(child, 80 + static_cast<int>(point));
        const auto resumed = PersistentNonceCounter::allocate(path, scope);
        const auto state_was_replaced =
            point == PersistencePoint::AfterReplace
            || point == PersistencePoint::AfterDirectorySync;
        const auto expected = state_was_replaced ? UINT64_C(2) : UINT64_C(1);
        require(resumed == nonce_from_counter(expected),
                "post-crash allocation did not match persistence point");
        if (state_was_replaced) {
            ++skipped;
        } else {
            ++preserved;
        }
    }
    std::cout << "process-crash points=4 old_state_preserved=" << preserved
              << " advanced_state_preserved=" << skipped
              << " returned_nonce_reuse=0\n";
}

void write_worker_allocations(
    const std::filesystem::path& state_path,
    const NonceScope128& scope,
    const std::filesystem::path& output_path) {
    std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
    if (!output) fail("cannot open worker output");
    for (std::size_t index = 0U; index < kAllocationsPerWorker; ++index) {
        const auto nonce = PersistentNonceCounter::allocate(state_path, scope);
        output.write(
            reinterpret_cast<const char*>(nonce.data()),
            static_cast<std::streamsize>(nonce.size()));
        if (!output) fail("cannot write worker output");
    }
    output.close();
    if (!output) fail("cannot close worker output");
}

void test_multiprocess(const std::filesystem::path& root) {
    const auto state_path = root / "multiprocess.state";
    const auto scope = scope_with_offset(UINT8_C(0x70));
    std::array<pid_t, kWorkers> children{};
    for (std::size_t worker = 0U; worker < kWorkers; ++worker) {
        const auto child = ::fork();
        if (child < 0) fail("fork failed in multiprocess test");
        if (child == 0) {
            try {
                write_worker_allocations(
                    state_path, scope, root / ("worker-" + std::to_string(worker) + ".bin"));
            } catch (...) {
                ::_exit(1);
            }
            ::_exit(0);
        }
        children[worker] = child;
    }
    for (const auto child : children) wait_for_expected_exit(child, 0);

    std::set<Nonce192> observed;
    for (std::size_t worker = 0U; worker < kWorkers; ++worker) {
        std::ifstream input(
            root / ("worker-" + std::to_string(worker) + ".bin"), std::ios::binary);
        if (!input) fail("cannot read worker output");
        for (std::size_t index = 0U; index < kAllocationsPerWorker; ++index) {
            Nonce192 nonce{};
            input.read(
                reinterpret_cast<char*>(nonce.data()),
                static_cast<std::streamsize>(nonce.size()));
            require(input.gcount() == static_cast<std::streamsize>(nonce.size()),
                    "worker output is truncated");
            require(observed.insert(nonce).second, "multiprocess nonce collision");
        }
        require(input.peek() == std::ifstream::traits_type::eof(),
                "worker output has trailing bytes");
    }
    const auto total = kWorkers * kAllocationsPerWorker;
    require(observed.size() == total, "multiprocess allocation count mismatch");
    for (std::size_t index = 0U; index < total; ++index) {
        require(observed.contains(nonce_from_counter(static_cast<std::uint64_t>(index))),
                "multiprocess allocation sequence has a gap");
    }
    require(PersistentNonceCounter::allocate(state_path, scope)
                == nonce_from_counter(static_cast<std::uint64_t>(total)),
            "multiprocess persisted high-water mark mismatch");
    std::cout << "multiprocess-allocation workers=" << kWorkers
              << " allocations_per_worker=" << kAllocationsPerWorker
              << " total=" << total << " collisions=0 gaps=0\n";
}

void test_snapshot_rollback(const std::filesystem::path& root) {
    const auto state_path = root / "rollback.state";
    const auto snapshot_path = root / "rollback.snapshot";
    const auto scope = scope_with_offset(UINT8_C(0xA0));
    for (std::uint64_t value = 0U; value < UINT64_C(8); ++value) {
        require(PersistentNonceCounter::allocate(state_path, scope)
                    == nonce_from_counter(value),
                "rollback prefix allocation mismatch");
    }
    std::filesystem::copy_file(state_path, snapshot_path);

    std::array<Nonce192, 8> first_branch{};
    for (std::size_t index = 0U; index < first_branch.size(); ++index) {
        first_branch[index] = PersistentNonceCounter::allocate(state_path, scope);
    }
    std::filesystem::copy_file(
        snapshot_path, state_path, std::filesystem::copy_options::overwrite_existing);

    NonceReuseDetector detector;
    const auto key = key_with_offset(UINT8_C(0x33));
    std::size_t repeated = 0U;
    for (const auto& nonce : first_branch) {
        require(detector.observe(key, nonce) == NonceObservation::Fresh,
                "rollback detector initial observation mismatch");
    }
    for (const auto& expected : first_branch) {
        const auto replayed = PersistentNonceCounter::allocate(state_path, scope);
        require(replayed == expected, "snapshot rollback did not repeat allocation");
        if (detector.observe(key, replayed) == NonceObservation::Reused) ++repeated;
    }
    require(repeated == first_branch.size(), "snapshot rollback reuse was not detected");
    std::cout << "snapshot-rollback repeated_nonces=" << repeated
              << " detector_caught=" << repeated
              << " counter_alone_prevents_rollback=0\n";
}

} // namespace

int main() {
    try {
        auto temporary = make_temporary_directory();
        std::cout << "PVC-RotSymEnc-1 nonce management and misuse campaign\n"
                  << "campaign_version=1\n"
                  << "construction_version=0.1.0-draft\n"
                  << "seed=0x4E4F4E43454D4754\n";
        test_reuse_detector_and_xor();
        run_collision_simulation();
        test_restart_and_scope(temporary.path);
        test_crash_points(temporary.path);
        test_multiprocess(temporary.path);
        test_snapshot_rollback(temporary.path);
        std::cout << "known_misuse_findings=2\n"
                  << "unexpected_failure_count=0\n"
                  << "interpretation=operational-prototype-not-a-security-proof\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "nonce campaign failure: " << error.what() << '\n';
        return 1;
    }
}
