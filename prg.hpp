#pragma once

#include <vector>
#include <cstdint>

namespace crypto {

template<typename T>
void fill_vector_with_prg(std::vector<T>& vec, uint64_t key, uint64_t seed) {
    // Dummy implementation: fill with zeros for now
    // In real implementation, use PRG to fill the vector
    for (auto& v : vec) {
        v = 0;
    }
}

} // namespace crypto