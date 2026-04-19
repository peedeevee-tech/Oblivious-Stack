#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>
#include <ostream>

#include "shares_local.hpp"
#include "mpcops_local.hpp"

/*
 * Oblivious stack over local secret shares.
 *
 * State:
 *   V[i] : additive shares of stack values
 *   R[i] : additive shares of occupancy flags
 *   s    : additive share of current size
 *
 * Unified operation:
 *   b = 1 => push(x)
 *   b = 0 => pop()
 *
 * Selector computation:
 *   delta_push_i = [s == i]
 *   delta_pop_i  = [s == i+1]
 *
 * The equality test is modeled using the local MPC primitive mpc_eqz,
 * which returns an XOR-shared bit, then converted to an additive-shared bit.
 *
 * Updates:
 *   V'_i = V_i + w_push_i * (x - V_i) - w_pop_i * V_i
 *   R'_i = R_i + w_push_i * (1 - R_i) - w_pop_i * R_i
 *   out  = sum_i w_pop_i * V_i
 *   s'   = s + 2b - 1
 */

namespace local_mpc {

class ObliviousStackShared {
public:
    using Share = AdditiveShare<uint64_t>;
    using XBit  = XorShare<uint64_t>;

    explicit ObliviousStackShared(std::size_t capacity)
        : capacity_(capacity),
          V_(capacity, public_additive<uint64_t>(0)),
          R_(capacity, public_additive<uint64_t>(0)),
          s_(public_additive<uint64_t>(0)) {
        if (capacity_ == 0) {
            throw std::runtime_error("ObliviousStackShared: capacity must be positive");
        }
    }

    std::size_t capacity() const { return capacity_; }

    void push(uint64_t plain_x) {
        if (reconstruct(s_) >= capacity_) {
            throw std::runtime_error("push on full stack");
        }
        Share x = share_secret_additive<uint64_t>(plain_x);
        (void) unified_operate(public_additive<uint64_t>(1), x);
    }

    Share push_shared(const Share& x) {
        if (reconstruct(s_) >= capacity_) {
            throw std::runtime_error("push on full stack");
        }
        return unified_operate(public_additive<uint64_t>(1), x);
    }

    Share pop() {
        if (reconstruct(s_) == 0) {
            throw std::runtime_error("pop on empty stack");
        }
        return unified_operate(public_additive<uint64_t>(0), public_additive<uint64_t>(0));
    }

    const Share& size_share() const { return s_; }
    const std::vector<Share>& values() const { return V_; }
    const std::vector<Share>& flags() const { return R_; }

    uint64_t size_plain() const { return reconstruct(s_); }

    std::vector<uint64_t> values_plain() const {
        std::vector<uint64_t> out;
        out.reserve(V_.size());
        for (const auto& v : V_) out.push_back(reconstruct(v));
        return out;
    }

    std::vector<uint64_t> flags_plain() const {
        std::vector<uint64_t> out;
        out.reserve(R_.size());
        for (const auto& r : R_) out.push_back(reconstruct(r));
        return out;
    }

    void print_state(std::ostream& os) const {
        os << "s = " << reconstruct(s_) << "\n";

        os << "V = [";
        for (std::size_t i = 0; i < V_.size(); ++i) {
            os << reconstruct(V_[i]);
            if (i + 1 < V_.size()) os << ", ";
        }
        os << "]\n";

        os << "R = [";
        for (std::size_t i = 0; i < R_.size(); ++i) {
            os << reconstruct(R_[i]);
            if (i + 1 < R_.size()) os << ", ";
        }
        os << "]\n";
    }

private:
    std::size_t capacity_;
    std::vector<Share> V_;
    std::vector<Share> R_;
    Share s_;

    Share indicator_at_size(std::size_t i) const {
        Share diff = s_ - public_additive<uint64_t>(static_cast<uint64_t>(i));
        XBit is_zero_x = mpc_eqz(diff);
        return xshare_bit_to_ashare(is_zero_x);
    }

    Share indicator_at_pop_index(std::size_t i) const {
        Share diff = s_ - public_additive<uint64_t>(static_cast<uint64_t>(i + 1));
        XBit is_zero_x = mpc_eqz(diff);
        return xshare_bit_to_ashare(is_zero_x);
    }

    Share unified_operate(const Share& b, const Share& x) {
        Share one = public_additive<uint64_t>(1);

        std::vector<Share> oldV = V_;
        std::vector<Share> oldR = R_;

        std::vector<Share> w_push(capacity_, public_additive<uint64_t>(0));
        std::vector<Share> w_pop(capacity_, public_additive<uint64_t>(0));

        for (std::size_t i = 0; i < capacity_; ++i) {
            Share delta_push = indicator_at_size(i);
            Share delta_pop  = indicator_at_pop_index(i);

            w_push[i] = b * delta_push;
            Share one_minus_b = one - b;
            w_pop[i] = one_minus_b * delta_pop;
        }

        Share out = public_additive<uint64_t>(0);

        for (std::size_t i = 0; i < capacity_; ++i) {
            Share push_term = w_push[i] * (x - oldV[i]);
            Share pop_term  = w_pop[i] * oldV[i];
            V_[i] = oldV[i] + push_term - pop_term;

            Share flag_push_term = w_push[i] * (one - oldR[i]);
            Share flag_pop_term  = w_pop[i] * oldR[i];
            R_[i] = oldR[i] + flag_push_term - flag_pop_term;

            out += (w_pop[i] * oldV[i]);
        }

        Share two_b = multiply_by_public(b, 2);
        s_ = s_ + two_b - one;

        return out;
    }
};

} // namespace local_mpc
