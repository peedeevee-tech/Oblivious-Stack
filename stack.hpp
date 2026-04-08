#pragma once

#include "shares.hpp"
#include "mpcops.hpp"
#include "network.hpp"
#include <vector>
#include <cstdint>
#include <boost/asio/awaitable.hpp>

using boost::asio::awaitable;

/**
 * @brief Oblivious Stack - A secure multi-party computation stack
 * 
 * Implements a stack data structure where:
 * - Operation type (push/pop) is hidden
 * - Stack size is hidden
 * - Memory access patterns are oblivious
 * 
 * Based on the protocol described in "Oblivious Stack Protocol in Multi-Party Computation"
 */
class ObliviousStack {
private:
    size_t capacity_;                          // Maximum stack capacity (N)
    MPCContext* ctx_;                          // MPC context
    std::vector<AShare<uint64_t>> values_;     // [V0], ..., [VN-1] - stack elements
    std::vector<AShare<uint64_t>> real_flags_; // [R0], ..., [RN-1] - validity flags (0 or 1)
    AShare<uint64_t> size_;                    // [s] - current stack size
    
    /**
     * @brief Compute equality indicator using Fermat's Little Theorem approach
     * @param diff The difference (s - i) or (s - (i+1))
     * @return Indicator that is 1 if diff == 0, otherwise 0
     */
    awaitable<AShare<uint64_t>> compute_indicator(const AShare<uint64_t>& diff);
    
    /**
     * @brief Perform modular exponentiation for Fermat's Little Theorem
     * @param base The base value
     * @param exponent The exponent (typically p-1)
     * @return base^exponent mod p
     */
    awaitable<AShare<uint64_t>> mpc_pow(const AShare<uint64_t>& base, uint64_t exponent);

public:
    /**
     * @brief Construct an oblivious stack
     * @param capacity Maximum number of elements the stack can hold
     * @param ctx MPC context containing role and peer information
     */
    explicit ObliviousStack(size_t capacity, MPCContext* ctx);
    
    /**
     * @brief Execute the unified oblivious operation
     * 
     * Performs either push or pop in a data-oblivious manner:
     * - When b = 1: pushes x onto the stack
     * - When b = 0: pops top element (x is ignored)
     * 
     * @param b Operation selector (1 = push, 0 = pop)
     * @param x Input value (used only when pushing)
     * @return The popped value (meaningful only when b = 0)
     */
    awaitable<AShare<uint64_t>> unified_operation(
        const AShare<uint64_t>& b,
        const AShare<uint64_t>& x
    );
    
    /**
     * @brief Push a value onto the stack (convenience wrapper)
     * @param x Value to push
     */
    awaitable<void> push(const AShare<uint64_t>& x);
    
    /**
     * @brief Pop a value from the stack (convenience wrapper)
     * @return The popped value
     */
    awaitable<AShare<uint64_t>> pop();
    
    /**
     * @brief Get the current stack size (as a secret share)
     * @return Secret-shared size
     */
    AShare<uint64_t> get_size() const { return size_; }
    
    /**
     * @brief Get the stack capacity
     * @return Maximum capacity
     */
    size_t get_capacity() const { return capacity_; }
};