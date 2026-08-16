#include "nonce_management/nonce_management.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <system_error>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace pvcrotsymenc1::research {
namespace {

constexpr std::array<std::uint8_t, 8> kStateMagic{
    'P', 'V', 'C', 'N', 'C', 'T', 'R', '1'};
constexpr std::size_t kScopeOffset = kStateMagic.size();
constexpr std::size_t kScopeComplementOffset = kScopeOffset + 16U;
constexpr std::size_t kExhaustedOffset = kScopeComplementOffset + 16U;
constexpr std::size_t kExhaustedComplementOffset = kExhaustedOffset + 1U;
constexpr std::size_t kNonceOffset = kExhaustedComplementOffset + 1U;
constexpr std::size_t kNonceComplementOffset = kNonceOffset + 24U;
constexpr std::size_t kStateBytes = kNonceComplementOffset + 24U;

struct CounterState {
    NonceScope128 scope{};
    Nonce192 next{};
    bool exhausted{};
};

class FileDescriptor {
public:
    explicit FileDescriptor(int value = -1) noexcept : value_(value) {}
    ~FileDescriptor() {
        if (value_ >= 0) {
            (void)::close(value_);
        }
    }

    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;

    [[nodiscard]] int get() const noexcept { return value_; }

private:
    int value_;
};

[[noreturn]] void throw_system_error(const char* operation) {
    throw std::system_error(errno, std::generic_category(), operation);
}

void invoke_hook(PersistenceHook hook, PersistencePoint point) {
    if (hook != nullptr) {
        hook(point);
    }
}

void write_all(int descriptor, const std::uint8_t* data, std::size_t size) {
    std::size_t offset = 0U;
    while (offset < size) {
        const auto written = ::write(descriptor, data + offset, size - offset);
        if (written < 0) {
            if (errno == EINTR) continue;
            throw_system_error("write nonce counter state");
        }
        if (written == 0) {
            throw std::runtime_error("zero-length nonce counter state write");
        }
        offset += static_cast<std::size_t>(written);
    }
}

void read_all(int descriptor, std::uint8_t* data, std::size_t size) {
    std::size_t offset = 0U;
    while (offset < size) {
        const auto received = ::read(descriptor, data + offset, size - offset);
        if (received < 0) {
            if (errno == EINTR) continue;
            throw_system_error("read nonce counter state");
        }
        if (received == 0) {
            throw std::runtime_error("truncated nonce counter state");
        }
        offset += static_cast<std::size_t>(received);
    }
}

std::array<std::uint8_t, kStateBytes> encode_state(const CounterState& state) {
    std::array<std::uint8_t, kStateBytes> encoded{};
    std::copy(kStateMagic.begin(), kStateMagic.end(), encoded.begin());
    for (std::size_t index = 0U; index < state.scope.size(); ++index) {
        encoded[kScopeOffset + index] = state.scope[index];
        encoded[kScopeComplementOffset + index] =
            static_cast<std::uint8_t>(~state.scope[index]);
    }
    encoded[kExhaustedOffset] = state.exhausted ? UINT8_C(1) : UINT8_C(0);
    encoded[kExhaustedComplementOffset] =
        static_cast<std::uint8_t>(~encoded[kExhaustedOffset]);
    for (std::size_t index = 0U; index < state.next.size(); ++index) {
        encoded[kNonceOffset + index] = state.next[index];
        encoded[kNonceComplementOffset + index] =
            static_cast<std::uint8_t>(~state.next[index]);
    }
    return encoded;
}

CounterState decode_state(const std::array<std::uint8_t, kStateBytes>& encoded) {
    if (!std::equal(kStateMagic.begin(), kStateMagic.end(), encoded.begin())) {
        throw std::runtime_error("nonce counter state magic mismatch");
    }
    CounterState state{};
    for (std::size_t index = 0U; index < state.scope.size(); ++index) {
        const auto value = encoded[kScopeOffset + index];
        if (encoded[kScopeComplementOffset + index]
            != static_cast<std::uint8_t>(~value)) {
            throw std::runtime_error("nonce counter scope redundancy mismatch");
        }
        state.scope[index] = value;
    }
    const auto exhausted = encoded[kExhaustedOffset];
    if (exhausted > UINT8_C(1)
        || encoded[kExhaustedComplementOffset]
            != static_cast<std::uint8_t>(~exhausted)) {
        throw std::runtime_error("nonce counter exhausted flag mismatch");
    }
    state.exhausted = exhausted == UINT8_C(1);
    for (std::size_t index = 0U; index < state.next.size(); ++index) {
        const auto value = encoded[kNonceOffset + index];
        if (encoded[kNonceComplementOffset + index]
            != static_cast<std::uint8_t>(~value)) {
            throw std::runtime_error("nonce counter value redundancy mismatch");
        }
        state.next[index] = value;
    }
    return state;
}

CounterState load_state(
    const std::filesystem::path& state_path,
    const NonceScope128& scope) {
    const FileDescriptor descriptor(::open(
        state_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (descriptor.get() < 0) {
        if (errno == ENOENT) {
            CounterState initial{};
            initial.scope = scope;
            return initial;
        }
        throw_system_error("open nonce counter state");
    }

    struct stat information {};
    if (::fstat(descriptor.get(), &information) != 0) {
        throw_system_error("stat nonce counter state");
    }
    if (information.st_size != static_cast<off_t>(kStateBytes)) {
        throw std::runtime_error("nonce counter state has an invalid size");
    }
    std::array<std::uint8_t, kStateBytes> encoded{};
    read_all(descriptor.get(), encoded.data(), encoded.size());
    auto state = decode_state(encoded);
    if (state.scope != scope) {
        throw std::invalid_argument("nonce counter scope does not match state file");
    }
    return state;
}

bool increment(Nonce192& nonce) {
    for (auto iterator = nonce.rbegin(); iterator != nonce.rend(); ++iterator) {
        if (*iterator != UINT8_MAX) {
            *iterator = static_cast<std::uint8_t>(*iterator + UINT8_C(1));
            return true;
        }
        *iterator = UINT8_C(0);
    }
    return false;
}

void persist_state(
    const std::filesystem::path& state_path,
    const CounterState& state,
    PersistenceHook hook) {
    const auto temporary_path = std::filesystem::path(state_path.string() + ".tmp");
    const FileDescriptor temporary(::open(
        temporary_path.c_str(),
        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
        S_IRUSR | S_IWUSR));
    if (temporary.get() < 0) {
        throw_system_error("open temporary nonce counter state");
    }
    if (::fchmod(temporary.get(), S_IRUSR | S_IWUSR) != 0) {
        throw_system_error("set nonce counter state permissions");
    }
    const auto encoded = encode_state(state);
    write_all(temporary.get(), encoded.data(), encoded.size());
    if (::fsync(temporary.get()) != 0) {
        throw_system_error("sync temporary nonce counter state");
    }
    invoke_hook(hook, PersistencePoint::AfterTemporarySync);

    if (::rename(temporary_path.c_str(), state_path.c_str()) != 0) {
        throw_system_error("replace nonce counter state");
    }
    invoke_hook(hook, PersistencePoint::AfterReplace);

    auto parent = state_path.parent_path();
    if (parent.empty()) parent = ".";
    const FileDescriptor directory(::open(
        parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (directory.get() < 0) {
        throw_system_error("open nonce counter directory");
    }
    if (::fsync(directory.get()) != 0) {
        throw_system_error("sync nonce counter directory");
    }
    invoke_hook(hook, PersistencePoint::AfterDirectorySync);
}

} // namespace

NonceObservation NonceReuseDetector::observe(
    const Key256& encryption_key,
    const Nonce192& nonce) {
    const auto [unused, inserted] = observations_.emplace(encryption_key, nonce);
    (void)unused;
    return inserted ? NonceObservation::Fresh : NonceObservation::Reused;
}

std::size_t NonceReuseDetector::observations() const noexcept {
    return observations_.size();
}

Nonce192 PersistentNonceCounter::allocate(
    const std::filesystem::path& state_path,
    const NonceScope128& scope,
    PersistenceHook hook) {
    const auto lock_path = std::filesystem::path(state_path.string() + ".lock");
    const FileDescriptor lock(::open(
        lock_path.c_str(),
        O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
        S_IRUSR | S_IWUSR));
    if (lock.get() < 0) {
        throw_system_error("open nonce counter lock");
    }
    if (::flock(lock.get(), LOCK_EX) != 0) {
        throw_system_error("lock nonce counter state");
    }
    invoke_hook(hook, PersistencePoint::AfterLock);

    const auto current = load_state(state_path, scope);
    if (current.exhausted) {
        throw std::overflow_error("192-bit nonce counter exhausted");
    }

    auto updated = current;
    const auto allocated = current.next;
    if (!increment(updated.next)) {
        updated.next = allocated;
        updated.exhausted = true;
    }
    persist_state(state_path, updated, hook);
    return allocated;
}

} // namespace pvcrotsymenc1::research
