#include <cstdlib>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "oblivious_queue_shared.hpp"

using local_mpc::AdditiveShare;
using local_mpc::ObliviousQueueShared;
using local_mpc::reconstruct;
using local_mpc::share_secret_additive;

namespace
{

    void fail(const std::string &msg)
    {
        std::cerr << "FAIL: " << msg << "\n";
        std::exit(1);
    }

    void expect_eq(uint64_t got, uint64_t expected, const std::string &msg)
    {
        if (got != expected)
        {
            fail(msg + " | expected " + std::to_string(expected) +
                 ", got " + std::to_string(got));
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

    void expect_state(const ObliviousQueueShared &q,
                      uint64_t size_expected,
                      const std::vector<uint64_t> &values_expected,
                      const std::vector<uint64_t> &flags_expected,
                      const std::string &label)
    {
        expect_eq(q.size_plain(), size_expected, label + " size");
        expect_vec_eq(q.values_plain(), values_expected, label + " values");
        expect_vec_eq(q.flags_plain(), flags_expected, label + " flags");
    }

    void test_sharing_basics()
    {
        std::cout << "Running test_sharing_basics...\n";

        uint64_t x = 0xDEADBEEFCAFEBABEULL;
        auto a = share_secret_additive<uint64_t>(x);
        expect_eq(reconstruct(a), x, "additive reconstruction");

        auto y = local_mpc::share_secret_xor<uint64_t>(x);
        expect_eq(reconstruct(y), x, "xor reconstruction");

        std::cout << "PASS: test_sharing_basics\n\n";
    }

    void test_single_enqueue_dequeue()
    {
        std::cout << "Running test_single_enqueue_dequeue...\n";

        ObliviousQueueShared q(4);
        expect_state(q, 0, {0, 0, 0, 0}, {0, 0, 0, 0}, "initial");

        q.enqueue(42);
        expect_state(q, 1, {42, 0, 0, 0}, {1, 0, 0, 0}, "after enqueue 42");

        auto out = q.dequeue();
        expect_eq(reconstruct(out), 42, "single dequeue output");
        expect_state(q, 0, {0, 0, 0, 0}, {0, 0, 0, 0}, "after dequeue");

        std::cout << "PASS: test_single_enqueue_dequeue\n\n";
    }

    void test_fifo_behavior()
    {
        std::cout << "Running test_fifo_behavior...\n";

        ObliviousQueueShared q(5);

        q.enqueue(10);
        q.enqueue(20);
        q.enqueue(30);
        expect_state(q, 3, {10, 20, 30, 0, 0}, {1, 1, 1, 0, 0}, "after enqueues");

        auto a = q.dequeue();
        auto b = q.dequeue();
        auto c = q.dequeue();

        // FIFO: first in, first out
        expect_eq(reconstruct(a), 10, "dequeue 1");
        expect_eq(reconstruct(b), 20, "dequeue 2");
        expect_eq(reconstruct(c), 30, "dequeue 3");

        expect_state(q, 0, {0, 0, 0, 0, 0}, {0, 0, 0, 0, 0}, "after all dequeues");

        std::cout << "PASS: test_fifo_behavior\n\n";
    }

    void test_interleaved_operations()
    {
        std::cout << "Running test_interleaved_operations...\n";

        ObliviousQueueShared q(4);

        q.enqueue(7);
        q.enqueue(9);
        auto a = q.dequeue();
        expect_eq(reconstruct(a), 7, "interleaved dequeue 1");
        expect_state(q, 1, {9, 0, 0, 0}, {1, 0, 0, 0}, "after first interleaved dequeue");

        q.enqueue(11);
        expect_state(q, 2, {9, 11, 0, 0}, {1, 1, 0, 0}, "after enqueue 11");

        auto b = q.dequeue();
        auto c = q.dequeue();
        expect_eq(reconstruct(b), 9, "interleaved dequeue 2");
        expect_eq(reconstruct(c), 11, "interleaved dequeue 3");

        expect_state(q, 0, {0, 0, 0, 0}, {0, 0, 0, 0}, "interleaved final state");

        std::cout << "PASS: test_interleaved_operations\n\n";
    }

    void test_shared_input_enqueue()
    {
        std::cout << "Running test_shared_input_enqueue...\n";

        ObliviousQueueShared q(3);

        AdditiveShare<uint64_t> secret_x = share_secret_additive<uint64_t>(55);
        q.enqueue_shared(secret_x);
        expect_state(q, 1, {55, 0, 0}, {1, 0, 0}, "after shared enqueue");

        auto out = q.dequeue();
        expect_eq(reconstruct(out), 55, "shared enqueue then dequeue");

        std::cout << "PASS: test_shared_input_enqueue\n\n";
    }

    void test_zero_values()
    {
        std::cout << "Running test_zero_values...\n";

        ObliviousQueueShared q(3);

        q.enqueue(0);
        q.enqueue(5);
        expect_state(q, 2, {0, 5, 0}, {1, 1, 0}, "after enqueuing zero and five");

        auto a = q.dequeue();
        auto b = q.dequeue();
        expect_eq(reconstruct(a), 0, "zero-values dequeue 1");
        expect_eq(reconstruct(b), 5, "zero-values dequeue 2");

        expect_state(q, 0, {0, 0, 0}, {0, 0, 0}, "zero-values final state");

        std::cout << "PASS: test_zero_values\n\n";
    }

    void test_capacity_boundary()
    {
        std::cout << "Running test_capacity_boundary...\n";

        ObliviousQueueShared q(2);

        q.enqueue(1);
        q.enqueue(2);
        expect_state(q, 2, {1, 2}, {1, 1}, "full queue");

        bool threw = false;
        try
        {
            q.enqueue(3);
        }
        catch (const std::runtime_error &)
        {
            threw = true;
        }
        expect_eq(threw ? 1 : 0, 1, "enqueue on full throws");

        auto a = q.dequeue();
        auto b = q.dequeue();
        expect_eq(reconstruct(a), 1, "full boundary dequeue 1");
        expect_eq(reconstruct(b), 2, "full boundary dequeue 2");

        threw = false;
        try
        {
            (void)q.dequeue();
        }
        catch (const std::runtime_error &)
        {
            threw = true;
        }
        expect_eq(threw ? 1 : 0, 1, "dequeue on empty throws");

        std::cout << "PASS: test_capacity_boundary\n\n";
    }

    void test_longer_sequence()
    {
        std::cout << "Running test_longer_sequence...\n";

        ObliviousQueueShared q(6);

        q.enqueue(3);
        q.enqueue(6);
        q.enqueue(9);
        auto a = q.dequeue(); // 3 (FIFO)
        q.enqueue(12);
        q.enqueue(15);
        auto b = q.dequeue(); // 6 (FIFO)
        auto c = q.dequeue(); // 9 (FIFO)
        q.enqueue(18);
        auto d = q.dequeue(); // 12 (FIFO)
        auto e = q.dequeue(); // 15 (FIFO)
        auto f = q.dequeue(); // 18 (FIFO)

        expect_eq(reconstruct(a), 3, "long sequence dequeue a");
        expect_eq(reconstruct(b), 6, "long sequence dequeue b");
        expect_eq(reconstruct(c), 9, "long sequence dequeue c");
        expect_eq(reconstruct(d), 12, "long sequence dequeue d");
        expect_eq(reconstruct(e), 15, "long sequence dequeue e");
        expect_eq(reconstruct(f), 18, "long sequence dequeue f");

        expect_state(q, 0, {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}, "long sequence final state");

        std::cout << "PASS: test_longer_sequence\n\n";
    }

    void test_multiple_shifts()
    {
        std::cout << "Running test_multiple_shifts...\n";

        ObliviousQueueShared q(4);

        // Fill the queue
        q.enqueue(100);
        q.enqueue(200);
        q.enqueue(300);
        q.enqueue(400);
        expect_state(q, 4, {100, 200, 300, 400}, {1, 1, 1, 1}, "full queue");

        // Dequeue twice to test shifting
        auto a = q.dequeue(); // Should get 100, shift others left
        expect_eq(reconstruct(a), 100, "first shift dequeue");
        expect_state(q, 3, {200, 300, 400, 0}, {1, 1, 1, 0}, "after first shift");

        auto b = q.dequeue(); // Should get 200, shift others left
        expect_eq(reconstruct(b), 200, "second shift dequeue");
        expect_state(q, 2, {300, 400, 0, 0}, {1, 1, 0, 0}, "after second shift");

        // Enqueue and dequeue more
        q.enqueue(500);
        expect_state(q, 3, {300, 400, 500, 0}, {1, 1, 1, 0}, "after enqueue 500");

        auto c = q.dequeue(); // Should get 300
        expect_eq(reconstruct(c), 300, "third shift dequeue");
        expect_state(q, 2, {400, 500, 0, 0}, {1, 1, 0, 0}, "after third shift");

        std::cout << "PASS: test_multiple_shifts\n\n";
    }

} // namespace

int main()
{
    try
    {
        test_sharing_basics();
        test_single_enqueue_dequeue();
        test_fifo_behavior();
        test_interleaved_operations();
        test_shared_input_enqueue();
        test_zero_values();
        test_capacity_boundary();
        test_longer_sequence();
        test_multiple_shifts();

        std::cout << "All local secret-share oblivious queue tests passed.\n";
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Unhandled exception: " << e.what() << "\n";
        return 1;
    }
}
