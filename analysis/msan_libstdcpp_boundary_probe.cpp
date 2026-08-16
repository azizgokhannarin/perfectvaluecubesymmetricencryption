#include <cstddef>
#include <iostream>
#include <vector>

void exercise_vectors() {
    std::vector<unsigned char> bytes;
    for (std::size_t i = 0; i < 512U; ++i) {
        bytes = std::vector<unsigned char>(64U, 0U);
    }
}

int main() {
    exercise_vectors();
    std::cout << 64U << '\n';
    return 0;
}
