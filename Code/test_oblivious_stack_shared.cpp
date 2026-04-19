#include <cstdlib>
#include <exception>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include "oblivious_stack_shared.hpp"

using local_mpc::AdditiveShare;
using local_mpc::ObliviousStackShared;
using local_mpc::reconstruct;
using local_mpc::share_secret_additive;

namespace
{

    void fail(const std::string &msg)
    {
        std::cerr << "FAIL: " << msg << "\n";
        std::exit(1);
    }

    void print_test_header(const std::string &name, const std::string &description)
    {
        std::cout << "Running " << name << "...\n";
        std::cout << "Purpose: " << description << "\n";
    }

    void print_test_pass(const std::string &name)
    {
        std::cout << "PASS: " << name << "\n\n";
    }

    void expect_eq(uint64_t got, uint64_t expected, const std::string &msg)
    {
        if (got != expected)
        {
            fail(msg + " | expected " + std::to_string(expected) +
                 ", got " + std::to_string(got));
        }
    }

    void expect_true(bool cond, const std::string &msg)
    {
        if (!cond)
        {
            fail(msg);
        }
    }

    void expect_vec_eq(const std::vector<uint64_t> &got,
                       const std::vector<uint64_t> &expected,
                       const std::string &msg)
    {
        if (got.size() != expected.size())
        {
            fail(msg + " | size mismatch");
        }
        for (std::size_t i = 0; i < got.size(); ++i)
        {
            if (got[i] != expected[i])
            {
                fail(msg + " | index " + std::to_string(i) +
                     ", expected " + std::to_string(expected[i]) +
                     ", got " + std::to_string(got[i]));
            }
        }
    }

    void expect_state(const ObliviousStackShared &st,
                      uint64_t size_expected,
                      const std::vector<uint64_t> &values_expected,
                      const std::vector<uint64_t> &flags_expected,
                      const std::string &label)
    {
        expect_eq(st.size_plain(), size_expected, label + " size");
        expect_vec_eq(st.values_plain(), values_expected, label + " values");
        expect_vec_eq(st.flags_plain(), flags_expected, label + " flags");
    }

    void expect_stack_invariants(const ObliviousStackShared &st,
                                 const std::string &label)
    {
        const uint64_t size = st.size_plain();
        const auto values = st.values_plain();
        const auto flags = st.flags_plain();

        expect_true(size <= values.size(), label + " | size exceeds capacity");
        expect_true(values.size() == flags.size(), label + " | values/flags size mismatch");

        for (std::size_t i = 0; i < flags.size(); ++i)
        {
            uint64_t expected_flag = (i < size) ? 1ULL : 0ULL;
            expect_eq(flags[i], expected_flag, label + " | prefix occupancy invariant");
            if (i >= size)
            {
                expect_eq(values[i], 0ULL, label + " | inactive slots should be zero");
            }
        }
    }

    void test_sharing_basics()
    {
        print_test_header(
            "test_sharing_basics",
            "Checks that additive and XOR secret-sharing reconstruct correctly to the original plaintext value.");

        uint64_t x = 0xDEADBEEFCAFEBABEULL;
        auto a = share_secret_additive<uint64_t>(x);
        expect_eq(reconstruct(a), x, "additive reconstruction");

        auto y = local_mpc::share_secret_xor<uint64_t>(x);
        expect_eq(reconstruct(y), x, "xor reconstruction");

        print_test_pass("test_sharing_basics");
    }

    void test_single_push_pop()
    {
        print_test_header(
            "test_single_push_pop",
            "Verifies basic correctness of one push followed by one pop and checks the resulting state.");

        ObliviousStackShared st(4);
        expect_state(st, 0, {0, 0, 0, 0}, {0, 0, 0, 0}, "initial");

        st.push(42);
        expect_state(st, 1, {42, 0, 0, 0}, {1, 0, 0, 0}, "after push 42");
        expect_stack_invariants(st, "after push 42");

        auto out = st.pop();
        expect_eq(reconstruct(out), 42, "single pop output");
        expect_state(st, 0, {0, 0, 0, 0}, {0, 0, 0, 0}, "after pop");
        expect_stack_invariants(st, "after pop");

        print_test_pass("test_single_push_pop");
    }

    void test_lifo_behavior()
    {
        print_test_header(
            "test_lifo_behavior",
            "Checks true LIFO behavior: the most recently pushed element must be popped first.");

        ObliviousStackShared st(5);

        st.push(10);
        st.push(20);
        st.push(30);
        expect_state(st, 3, {10, 20, 30, 0, 0}, {1, 1, 1, 0, 0}, "after pushes");
        expect_stack_invariants(st, "after pushes");

        auto a = st.pop();
        auto b = st.pop();
        auto c = st.pop();

        expect_eq(reconstruct(a), 30, "pop 1");
        expect_eq(reconstruct(b), 20, "pop 2");
        expect_eq(reconstruct(c), 10, "pop 3");

        expect_state(st, 0, {0, 0, 0, 0, 0}, {0, 0, 0, 0, 0}, "after all pops");
        expect_stack_invariants(st, "after all pops");

        print_test_pass("test_lifo_behavior");
    }

    void test_interleaved_operations()
    {
        print_test_header(
            "test_interleaved_operations",
            "Tests mixed push and pop operations to ensure correctness is preserved across changing states.");

        ObliviousStackShared st(4);

        st.push(7);
        st.push(9);
        expect_stack_invariants(st, "after pushing 7 and 9");

        auto a = st.pop();
        expect_eq(reconstruct(a), 9, "interleaved pop 1");
        expect_state(st, 1, {7, 0, 0, 0}, {1, 0, 0, 0}, "after first interleaved pop");
        expect_stack_invariants(st, "after first interleaved pop");

        st.push(11);
        expect_state(st, 2, {7, 11, 0, 0}, {1, 1, 0, 0}, "after push 11");
        expect_stack_invariants(st, "after push 11");

        auto b = st.pop();
        auto c = st.pop();
        expect_eq(reconstruct(b), 11, "interleaved pop 2");
        expect_eq(reconstruct(c), 7, "interleaved pop 3");

        expect_state(st, 0, {0, 0, 0, 0}, {0, 0, 0, 0}, "interleaved final state");
        expect_stack_invariants(st, "interleaved final state");

        print_test_pass("test_interleaved_operations");
    }

    void test_shared_input_push()
    {
        print_test_header(
            "test_shared_input_push",
            "Ensures the stack works correctly when inputs are already provided as additive secret shares.");

        ObliviousStackShared st(3);

        AdditiveShare<uint64_t> secret_x = share_secret_additive<uint64_t>(55);
        st.push_shared(secret_x);
        expect_state(st, 1, {55, 0, 0}, {1, 0, 0}, "after shared push");
        expect_stack_invariants(st, "after shared push");

        auto out = st.pop();
        expect_eq(reconstruct(out), 55, "shared push then pop");
        expect_stack_invariants(st, "after shared push then pop");

        print_test_pass("test_shared_input_push");
    }

    void test_zero_values()
    {
        print_test_header(
            "test_zero_values",
            "Checks that storing an actual data value 0 does not interfere with protocol logic or equality-based primitives.");

        ObliviousStackShared st(3);

        st.push(0);
        st.push(5);
        expect_state(st, 2, {0, 5, 0}, {1, 1, 0}, "after pushing zero and five");
        expect_stack_invariants(st, "after pushing zero and five");

        auto a = st.pop();
        auto b = st.pop();
        expect_eq(reconstruct(a), 5, "zero-values pop 1");
        expect_eq(reconstruct(b), 0, "zero-values pop 2");

        expect_state(st, 0, {0, 0, 0}, {0, 0, 0}, "zero-values final state");
        expect_stack_invariants(st, "zero-values final state");

        print_test_pass("test_zero_values");
    }

    void test_capacity_boundary()
    {
        print_test_header(
            "test_capacity_boundary",
            "Checks correct behavior at capacity limits, including errors on push to full stack and pop from empty stack.");

        ObliviousStackShared st(2);

        st.push(1);
        st.push(2);
        expect_state(st, 2, {1, 2}, {1, 1}, "full stack");
        expect_stack_invariants(st, "full stack");

        bool threw = false;
        try
        {
            st.push(3);
        }
        catch (const std::runtime_error &)
        {
            threw = true;
        }
        expect_eq(threw ? 1 : 0, 1, "push on full throws");

        auto a = st.pop();
        auto b = st.pop();
        expect_eq(reconstruct(a), 2, "full boundary pop 1");
        expect_eq(reconstruct(b), 1, "full boundary pop 2");
        expect_stack_invariants(st, "after removing all from full stack");

        threw = false;
        try
        {
            (void)st.pop();
        }
        catch (const std::runtime_error &)
        {
            threw = true;
        }
        expect_eq(threw ? 1 : 0, 1, "pop on empty throws");

        print_test_pass("test_capacity_boundary");
    }

    void test_capacity_one_corner_case()
    {
        print_test_header(
            "test_capacity_one_corner_case",
            "Tests the smallest non-trivial stack to catch indexing and boundary-condition bugs.");

        ObliviousStackShared st(1);

        expect_state(st, 0, {0}, {0}, "initial");
        expect_stack_invariants(st, "initial");

        st.push(99);
        expect_state(st, 1, {99}, {1}, "after push");
        expect_stack_invariants(st, "after push");

        auto out = st.pop();
        expect_eq(reconstruct(out), 99, "capacity-1 pop");
        expect_state(st, 0, {0}, {0}, "after pop");
        expect_stack_invariants(st, "after pop");

        bool threw = false;
        try
        {
            (void)st.pop();
        }
        catch (const std::runtime_error &)
        {
            threw = true;
        }
        expect_true(threw, "capacity-1 pop on empty should throw");

        print_test_pass("test_capacity_one_corner_case");
    }

    void test_longer_sequence()
    {
        print_test_header(
            "test_longer_sequence",
            "Runs a longer hand-crafted sequence of operations to verify stability over multiple state transitions.");

        ObliviousStackShared st(6);

        st.push(3);
        st.push(6);
        st.push(9);
        expect_stack_invariants(st, "after first three pushes");

        auto a = st.pop(); // 9
        st.push(12);
        st.push(15);
        auto b = st.pop(); // 15
        auto c = st.pop(); // 12
        st.push(18);
        auto d = st.pop(); // 18
        auto e = st.pop(); // 6
        auto f = st.pop(); // 3

        expect_eq(reconstruct(a), 9, "long sequence pop a");
        expect_eq(reconstruct(b), 15, "long sequence pop b");
        expect_eq(reconstruct(c), 12, "long sequence pop c");
        expect_eq(reconstruct(d), 18, "long sequence pop d");
        expect_eq(reconstruct(e), 6, "long sequence pop e");
        expect_eq(reconstruct(f), 3, "long sequence pop f");

        expect_state(st, 0, {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}, "long sequence final state");
        expect_stack_invariants(st, "long sequence final state");

        print_test_pass("test_longer_sequence");
    }

    void test_reference_comparison()
    {
        print_test_header(
            "test_reference_comparison",
            "Compares the oblivious stack against a plain reference stack over a deterministic sequence of operations.");

        ObliviousStackShared st(8);
        std::vector<uint64_t> ref;

        auto ref_push = [&](uint64_t x)
        {
            ref.push_back(x);
            st.push(x);
        };

        auto ref_pop = [&]()
        {
            if (ref.empty())
            {
                fail("reference stack unexpectedly empty");
            }
            uint64_t expected = ref.back();
            ref.pop_back();
            uint64_t got = reconstruct(st.pop());
            expect_eq(got, expected, "reference comparison pop mismatch");
        };

        ref_push(5);
        ref_push(8);
        ref_push(13);
        ref_pop(); // 13
        ref_push(21);
        ref_pop(); // 21
        ref_push(34);
        ref_push(55);
        ref_pop(); // 55
        ref_pop(); // 34
        ref_pop(); // 8
        ref_pop(); // 5

        expect_eq(st.size_plain(), 0, "reference comparison final size");
        expect_stack_invariants(st, "reference comparison final state");

        print_test_pass("test_reference_comparison");
    }

    void test_randomized_against_reference()
    {
        print_test_header(
            "test_randomized_against_reference",
            "Performs randomized push/pop operations and checks each step against a standard reference stack.");

        constexpr std::size_t CAP = 10;
        constexpr int OPS = 200;

        ObliviousStackShared st(CAP);
        std::vector<uint64_t> ref;

        std::mt19937_64 rng(123456789ULL);
        std::uniform_int_distribution<uint64_t> val_dist(0, 1000000);
        std::uniform_int_distribution<int> op_dist(0, 1);

        for (int step = 0; step < OPS; ++step)
        {
            bool do_push;
            if (ref.empty())
            {
                do_push = true;
            }
            else if (ref.size() == CAP)
            {
                do_push = false;
            }
            else
            {
                do_push = (op_dist(rng) == 1);
            }

            if (do_push)
            {
                uint64_t x = val_dist(rng);
                ref.push_back(x);
                st.push(x);
            }
            else
            {
                uint64_t expected = ref.back();
                ref.pop_back();
                uint64_t got = reconstruct(st.pop());
                expect_eq(got, expected, "randomized reference pop mismatch at step " + std::to_string(step));
            }

            expect_eq(st.size_plain(), ref.size(), "randomized reference size mismatch at step " + std::to_string(step));
            expect_stack_invariants(st, "randomized reference invariant check at step " + std::to_string(step));
        }

        while (!ref.empty())
        {
            uint64_t expected = ref.back();
            ref.pop_back();
            uint64_t got = reconstruct(st.pop());
            expect_eq(got, expected, "randomized drain mismatch");
            expect_stack_invariants(st, "randomized drain invariant check");
        }

        expect_eq(st.size_plain(), 0, "randomized final empty size");
        expect_stack_invariants(st, "randomized final empty state");

        print_test_pass("test_randomized_against_reference");
    }

} // namespace

int main()
{
    try
    {
        test_sharing_basics();
        test_single_push_pop();
        test_lifo_behavior();
        test_interleaved_operations();
        test_shared_input_push();
        test_zero_values();
        test_capacity_boundary();
        test_capacity_one_corner_case();
        test_longer_sequence();
        test_reference_comparison();
        test_randomized_against_reference();

        std::cout << "All local secret-share oblivious stack tests passed.\n";
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Unhandled exception: " << e.what() << "\n";
        return 1;
    }
}