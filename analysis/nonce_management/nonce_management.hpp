#pragma once

#include "pvcrotsymenc1/symmetric_encryption.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <set>
#include <utility>

namespace pvcrotsymenc1::research {

enum class NonceObservation : std::uint8_t {
    Fresh,
    Reused,
};

class NonceReuseDetector {
public:
    [[nodiscard]] NonceObservation observe(
        const Key256& encryption_key,
        const Nonce192& nonce);

    [[nodiscard]] std::size_t observations() const noexcept;

private:
    std::set<std::pair<Key256, Nonce192>> observations_;
};

using NonceScope128 = std::array<std::uint8_t, 16>;

enum class PersistencePoint : std::uint8_t {
    AfterLock,
    AfterTemporarySync,
    AfterReplace,
    AfterDirectorySync,
};

using PersistenceHook = void (*)(PersistencePoint);

class PersistentNonceCounter {
public:
    // The caller must provision a distinct, non-secret scope identifier and
    // state path for every encryption key. No key-derived identifier is added
    // to the candidate construction by this research prototype.
    [[nodiscard]] static Nonce192 allocate(
        const std::filesystem::path& state_path,
        const NonceScope128& scope,
        PersistenceHook hook = nullptr);
};

} // namespace pvcrotsymenc1::research
