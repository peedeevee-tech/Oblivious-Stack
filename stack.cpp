#include "stack.hpp"
#include <stdexcept>
#include <iostream>

/**
 * @brief Convert XShare to AShare (for boolean values)
 * 
 * This is a helper function to convert a boolean XShare (0 or 1) to an AShare.
 * Both parties convert their shares independently without communication.
 * 
 * NOTE: This works because for boolean values in {0,1}, the XOR share can be
 * treated as an additive share in a ring.
 */
static AShare<uint64_t> xshare_to_ashare(const XShare<uint64_t>& xs, MPCContext* ctx) {
    return AShare<uint64_t>(xs.val, ctx);
}

ObliviousStack::ObliviousStack(size_t capacity, MPCContext* ctx)
    : capacity_(capacity), ctx_(ctx), size_(0, ctx)
{
    if (capacity == 0) {
        throw std::runtime_error("Stack capacity must be > 0");
    }
    
    // Initialize value array with zeros
    values_.reserve(capacity);
    for (size_t i = 0; i < capacity; ++i) {
        values_.emplace_back(0, ctx);
    }
    
    // Initialize real flags with zeros (all positions invalid initially)
    real_flags_.reserve(capacity);
    for (size_t i = 0; i < capacity; ++i) {
        real_flags_.emplace_back(0, ctx);
    }
    
    std::cout << "[ObliviousStack] Initialized with capacity " << capacity << std::endl;
}

awaitable<AShare<uint64_t>> ObliviousStack::mpc_pow(
    const AShare<uint64_t>& base,
    uint64_t exponent)
{
    // Square-and-multiply algorithm for exponentiation
    // Computes base^exponent using O(log exponent) multiplications
    
    if (exponent == 0) {
        co_return AShare<uint64_t>(1, ctx_);
    }
    
    if (exponent == 1) {
        co_return base;
    }
    
    AShare<uint64_t> result(1, ctx_);
    AShare<uint64_t> current_base = base;
    
    uint64_t exp = exponent;
    while (exp > 0) {
        if (exp & 1) {
            // Multiply result by current_base
            result = co_await (result * current_base);
        }
        
        exp >>= 1;
        if (exp > 0) {
            // Square current_base
            current_base = co_await (current_base * current_base);
        }
    }
    
    co_return result;
}

awaitable<AShare<uint64_t>> ObliviousStack::compute_indicator(
    const AShare<uint64_t>& diff)
{
    // Compute indicator: δ = 1 if diff == 0, else 0
    // Using Fermat's Little Theorem: δ = 1 - diff^(p-1)
    // 
    // For p = 2^61 - 1 (Mersenne prime), p-1 = 2^61 - 2
    // This requires ~61 multiplications via square-and-multiply
    //
    // Alternatively, we can use the mpc_eqz operation for efficiency
    
    // Use mpc_eqz which tests if value equals zero
    XShare<uint64_t> is_zero = co_await (diff == 0);
    
    // Convert XShare boolean to AShare
    // This works for {0,1} values where XOR and addition are equivalent mod 2
    AShare<uint64_t> indicator = xshare_to_ashare(is_zero, ctx_);
    
    co_return indicator;
}

awaitable<AShare<uint64_t>> ObliviousStack::unified_operation(
    const AShare<uint64_t>& b,
    const AShare<uint64_t>& x)
{
    // The unified oblivious operation:
    // - When b = 1: push x
    // - When b = 0: pop and return top element
    
    std::cout << "[ObliviousStack] Executing unified operation..." << std::endl;
    
    // Output accumulator for pop
    AShare<uint64_t> output(0, ctx_);
    
    // Temporary storage for updated values and flags
    std::vector<AShare<uint64_t>> new_values;
    std::vector<AShare<uint64_t>> new_flags;
    new_values.reserve(capacity_);
    new_flags.reserve(capacity_);
    
    // Process each index i ∈ {0, ..., N-1}
    for (size_t i = 0; i < capacity_; ++i) {
        // Compute indicators
        // δ_i^push = 1 if s == i, else 0
        AShare<uint64_t> diff_push = size_ - AShare<uint64_t>(i, ctx_);
        AShare<uint64_t> delta_push = co_await compute_indicator(diff_push);
        
        // δ_i^pop = 1 if s == i+1, else 0
        AShare<uint64_t> diff_pop = size_ - AShare<uint64_t>(i + 1, ctx_);
        AShare<uint64_t> delta_pop = co_await compute_indicator(diff_pop);
        
        // Compute weights
        // w_i^push = b · δ_i^push
        AShare<uint64_t> w_push = co_await (b * delta_push);
        
        // w_i^pop = (1 - b) · δ_i^pop
        AShare<uint64_t> one_minus_b = AShare<uint64_t>(1, ctx_) - b;
        AShare<uint64_t> w_pop = co_await (one_minus_b * delta_pop);
        
        // Update value at index i:
        // V'_i = V_i + w_i^push · (x - V_i) - w_i^pop · V_i
        AShare<uint64_t> x_minus_vi = x - values_[i];
        AShare<uint64_t> push_term = co_await (w_push * x_minus_vi);
        AShare<uint64_t> pop_term = co_await (w_pop * values_[i]);
        AShare<uint64_t> new_vi = values_[i] + push_term - pop_term;
        
        // Update flag at index i:
        // R'_i = R_i + w_i^push · (1 - R_i) - w_i^pop · R_i
        AShare<uint64_t> one_minus_ri = AShare<uint64_t>(1, ctx_) - real_flags_[i];
        AShare<uint64_t> push_flag_term = co_await (w_push * one_minus_ri);
        AShare<uint64_t> pop_flag_term = co_await (w_pop * real_flags_[i]);
        AShare<uint64_t> new_ri = real_flags_[i] + push_flag_term - pop_flag_term;
        
        // Accumulate output (for pop operation):
        // out = Σ w_i^pop · V_i
        AShare<uint64_t> output_contrib = co_await (w_pop * values_[i]);
        output = output + output_contrib;
        
        // Store new values
        new_values.push_back(new_vi);
        new_flags.push_back(new_ri);
    }
    
    // Update state
    values_ = std::move(new_values);
    real_flags_ = std::move(new_flags);
    
    // Update size: s' = s + 2b - 1
    // When b = 1 (push): s' = s + 1
    // When b = 0 (pop):  s' = s - 1
    AShare<uint64_t> two_b = co_await (b * AShare<uint64_t>(2, ctx_));
    size_ = size_ + two_b - AShare<uint64_t>(1, ctx_);
    
    std::cout << "[ObliviousStack] Unified operation complete" << std::endl;
    
    co_return output;
}

awaitable<void> ObliviousStack::push(const AShare<uint64_t>& x) {
    std::cout << "[ObliviousStack] Push operation" << std::endl;
    
    // Execute unified operation with b = 1 (push)
    AShare<uint64_t> b(1, ctx_);
    co_await unified_operation(b, x);
    
    co_return;
}

awaitable<AShare<uint64_t>> ObliviousStack::pop() {
    std::cout << "[ObliviousStack] Pop operation" << std::endl;
    
    // Execute unified operation with b = 0 (pop), x is ignored
    AShare<uint64_t> b(0, ctx_);
    AShare<uint64_t> dummy_x(0, ctx_);
    AShare<uint64_t> result = co_await unified_operation(b, dummy_x);
    
    co_return result;
}