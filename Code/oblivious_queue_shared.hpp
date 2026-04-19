#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>
#include <ostream>

#include "shares_local.hpp"
#include "mpcops_local.hpp"

/*
 * Oblivious queue over local secret shares.
 *
 * State:
 *   V[i] : additive shares of queue values
 *   R[i] : additive shares of occupancy flags
 *   s    : additive share of current size
 *
 * Unified operation:
 *   b = 1 => enqueue(x)
 *   b = 0 => dequeue()
 *
 * Selector computation:
 *   delta_enqueue_i = [s == i]
 *   delta_dequeue_i = [i == 0]
 *
 * The equality test is modeled using the local MPC primitive mpc_eqz,
 * which returns an XOR-shared bit, then converted to an additive-shared bit.
 *
 * Updates:
 *   V'_i = V_i + w_enqueue_i * (x - V_i) - w_dequeue_i * V_i
 *   R'_i = R_i + w_enqueue_i * (1 - R_i) - w_dequeue_i * R_i
 *   
 * After dequeue (b=0), obliviously shift all elements left:
 *   V''_i = b * V'_i + (1-b) * V'_{i+1}  (for i < N-1)
 *   V''_{N-1} = b * V'_{N-1}
 *   
 *   out  = sum_i w_dequeue_i * V_i
 *   s'   = s + 2b - 1
 */

namespace local_mpc {

class ObliviousQueueShared {
public:
    using Share = AdditiveShare<uint64_t>;
    using XBit  = XorShare<uint64_t>;

    explicit ObliviousQueueShared(std::size_t capacity)
        : capacity_(capacity),
          V_(capacity, public_additive<uint64_t>(0)),
          R_(capacity, public_additive<uint64_t>(0)),
          s_(public_additive<uint64_t>(0)) {
        if (capacity_ == 0) {
            throw std::runtime_error("ObliviousQueueShared: capacity must be positive");
        }
    }

    std::size_t capacity() const { return capacity_; }

    void enqueue(uint64_t plain_x) {
        if (reconstruct(s_) >= capacity_) {
            throw std::runtime_error("enqueue on full queue");
        }
        Share x = share_secret_additive<uint64_t>(plain_x);
        (void) unified_operate(public_additive<uint64_t>(1), x);
    }

    Share enqueue_shared(const Share& x) {
        if (reconstruct(s_) >= capacity_) {
            throw std::runtime_error("enqueue on full queue");
        }
        return unified_operate(public_additive<uint64_t>(1), x);
    }

    Share dequeue() {
        if (reconstruct(s_) == 0) {
            throw std::runtime_error("dequeue on empty queue");
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
        XBit is_zero_x = (diff == static_cast<uint64_t>(0));
        return xshare_bit_to_ashare(is_zero_x);
    }

    Share indicator_at_dequeue_index(std::size_t i) const {
        // For queue, dequeue always happens at index 0
        Share idx = public_additive<uint64_t>(static_cast<uint64_t>(i));
        XBit is_zero_x = (idx == static_cast<uint64_t>(0));
        return xshare_bit_to_ashare(is_zero_x);
    }

    Share unified_operate(const Share& b, const Share& x) {
        Share one = public_additive<uint64_t>(1);
        Share zero = public_additive<uint64_t>(0);

        std::vector<Share> oldV = V_;
        std::vector<Share> oldR = R_;

        std::vector<Share> w_enqueue(capacity_, zero);
        std::vector<Share> w_dequeue(capacity_, zero);

        for (std::size_t i = 0; i < capacity_; ++i) {
            Share delta_enqueue = indicator_at_size(i);
            Share delta_dequeue = indicator_at_dequeue_index(i);

            w_enqueue[i] = b * delta_enqueue;
            Share one_minus_b = one - b;
            w_dequeue[i] = one_minus_b * delta_dequeue;
        }

        Share out = zero;

        // First update: enqueue/dequeue operation
        for (std::size_t i = 0; i < capacity_; ++i) {
            Share enqueue_term = w_enqueue[i] * (x - oldV[i]);
            Share dequeue_term = w_dequeue[i] * oldV[i];
            V_[i] = oldV[i] + enqueue_term - dequeue_term;

            Share flag_enqueue_term = w_enqueue[i] * (one - oldR[i]);
            Share flag_dequeue_term = w_dequeue[i] * oldR[i];
            R_[i] = oldR[i] + flag_enqueue_term - flag_dequeue_term;

            out += (w_dequeue[i] * oldV[i]);
        }

        // Second phase: Oblivious shift for dequeue
        // When b=0 (dequeue), shift all elements left
        // When b=1 (enqueue), keep elements as is
        std::vector<Share> preShiftV = V_;
        std::vector<Share> preShiftR = R_;
        
        Share one_minus_b = one - b;

        for (std::size_t i = 0; i < capacity_; ++i) {
            if (i + 1 < capacity_) {
                // If dequeuing (b=0): V[i] = V[i+1]
                // If enqueuing (b=1): V[i] = V[i]
                V_[i] = b * preShiftV[i] + one_minus_b * preShiftV[i + 1];
                R_[i] = b * preShiftR[i] + one_minus_b * preShiftR[i + 1];
            } else {
                // Last element: keep if enqueuing, zero if dequeuing
                V_[i] = b * preShiftV[i];
                R_[i] = b * preShiftR[i];
            }
        }

        // Update size: s' = s + 2b - 1
        Share two_b = multiply_by_public(b, 2);
        s_ = s_ + two_b - one;

        return out;
    }
};

} // namespace local_mpc
