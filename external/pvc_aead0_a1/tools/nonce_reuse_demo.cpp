#include "pvcaead0/aead.hpp"

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

int main() {
    pvcaead0::KeyPair512 keys{};
    pvcaead0::Nonce192 nonce{};
    const std::vector<std::uint8_t> ad{'d','e','m','o'};
    const std::vector<std::uint8_t> p1{'m','e','s','s','a','g','e','-','o','n','e'};
    const std::vector<std::uint8_t> p2{'m','e','s','s','a','g','e','-','t','w','o'};
    const auto a = pvcaead0::seal(keys, nonce, ad, p1);
    const auto b = pvcaead0::seal(keys, nonce, ad, p2);
    bool relation = a.ciphertext.size() == b.ciphertext.size() && p1.size() == p2.size();
    for (std::size_t i = 0; relation && i < p1.size(); ++i) {
        relation = static_cast<std::uint8_t>(a.ciphertext[i] ^ b.ciphertext[i])
            == static_cast<std::uint8_t>(p1[i] ^ p2[i]);
    }
    std::cout << "same_nonce_xor_relation=" << (relation ? "observed" : "not_observed") << '\n';
    std::cout << "warning=nonce reuse under one encryption key breaks confidentiality\n";
    return relation ? 0 : 1;
}
