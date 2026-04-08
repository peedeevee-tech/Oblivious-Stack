#include "stack.hpp"
#include "shares.hpp"
#include "network.hpp"
#include "mpcops.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <cassert>
#include <boost/asio.hpp>

using boost::asio::awaitable;
using boost::asio::co_spawn;
using boost::asio::detached;
using boost::asio::io_context;

// Test configuration
constexpr uint16_t BASE_PORT = 8080;
constexpr size_t STACK_CAPACITY = 8;

/**
 * @brief Test basic push and pop operations
 */
awaitable<void> test_party(Role role, NetContext& net_ctx) {
    std::cout << "[Party " << static_cast<int>(role) << "] Starting test..." << std::endl;
    
    // Set up MPC context
    MPCContext mpc_ctx(role, net_ctx.peer(Role::P2));
    
    if (role == Role::P0) {
        mpc_ctx.peer0 = &net_ctx.peer(Role::P1);
        mpc_ctx.peer1 = nullptr;
    } else if (role == Role::P1) {
        mpc_ctx.peer0 = &net_ctx.peer(Role::P0);
        mpc_ctx.peer1 = nullptr;
    } else if (role == Role::P2) {
        mpc_ctx.peer0 = &net_ctx.peer(Role::P0);
        mpc_ctx.peer1 = &net_ctx.peer(Role::P1);
    }
    
    // Create oblivious stack
    ObliviousStack stack(STACK_CAPACITY, &mpc_ctx);
    
    // Test 1: Push three values
    std::cout << "[Party " << static_cast<int>(role) << "] Test 1: Pushing values..." << std::endl;
    
    uint64_t val1 = 42;
    uint64_t val2 = 123;
    uint64_t val3 = 789;
    
    // Create secret shares for the values
    AShare<uint64_t> share1(0, &mpc_ctx);
    AShare<uint64_t> share2(0, &mpc_ctx);
    AShare<uint64_t> share3(0, &mpc_ctx);
    
    if (role == Role::P0) {
        share1 = AShare<uint64_t>(val1, &mpc_ctx);
        share2 = AShare<uint64_t>(val2, &mpc_ctx);
        share3 = AShare<uint64_t>(val3, &mpc_ctx);
    } else {
        share1 = AShare<uint64_t>(0, &mpc_ctx);
        share2 = AShare<uint64_t>(0, &mpc_ctx);
        share3 = AShare<uint64_t>(0, &mpc_ctx);
    }
    
    // Push values onto stack
    co_await stack.push(share1);
    std::cout << "[Party " << static_cast<int>(role) << "] Pushed value 1" << std::endl;
    
    co_await stack.push(share2);
    std::cout << "[Party " << static_cast<int>(role) << "] Pushed value 2" << std::endl;
    
    co_await stack.push(share3);
    std::cout << "[Party " << static_cast<int>(role) << "] Pushed value 3" << std::endl;
    
    // Test 2: Pop values and verify (in LIFO order)
    std::cout << "[Party " << static_cast<int>(role) << "] Test 2: Popping values..." << std::endl;
    
    AShare<uint64_t> popped3 = co_await stack.pop();
    std::cout << "[Party " << static_cast<int>(role) << "] Popped value 3" << std::endl;
    
    AShare<uint64_t> popped2 = co_await stack.pop();
    std::cout << "[Party " << static_cast<int>(role) << "] Popped value 2" << std::endl;
    
    AShare<uint64_t> popped1 = co_await stack.pop();
    std::cout << "[Party " << static_cast<int>(role) << "] Popped value 1" << std::endl;
    
    // Reconstruct and verify results
    if (role == Role::P0) {
        uint64_t reconstructed3 = co_await reconstruct_remote(
            net_ctx.peer(Role::P1), popped3);
        uint64_t reconstructed2 = co_await reconstruct_remote(
            net_ctx.peer(Role::P1), popped2);
        uint64_t reconstructed1 = co_await reconstruct_remote(
            net_ctx.peer(Role::P1), popped1);
        
        std::cout << "[Party 0] Reconstructed values:" << std::endl;
        std::cout << "  popped3 = " << reconstructed3 << " (expected " << val3 << ")" << std::endl;
        std::cout << "  popped2 = " << reconstructed2 << " (expected " << val2 << ")" << std::endl;
        std::cout << "  popped1 = " << reconstructed1 << " (expected " << val1 << ")" << std::endl;
        
        if (reconstructed3 == val3 && reconstructed2 == val2 && reconstructed1 == val1) {
            std::cout << "[Party 0] ✓ All tests PASSED!" << std::endl;
        } else {
            std::cout << "[Party 0] ✗ Test FAILED - values don't match!" << std::endl;
        }
    } else if (role == Role::P1) {
        co_await reconstruct_remote(net_ctx.peer(Role::P0), popped3);
        co_await reconstruct_remote(net_ctx.peer(Role::P0), popped2);
        co_await reconstruct_remote(net_ctx.peer(Role::P0), popped1);
    }
    
    std::cout << "[Party " << static_cast<int>(role) << "] Test complete!" << std::endl;
    co_return;
}

/**
 * @brief Party 0 (server, receives connections)
 */
awaitable<void> party0_main(io_context& io) {
    std::cout << "[Party 0] Waiting for connections..." << std::endl;
    
    NetContext net(Role::P0);
    
    // Accept connection from P1
    auto sock1 = co_await make_server(io, BASE_PORT + 1);
    net.add_peer(Role::P1, std::move(sock1));
    std::cout << "[Party 0] Connected to Party 1" << std::endl;
    
    // Accept connection from P2
    auto sock2 = co_await make_server(io, BASE_PORT + 2);
    net.add_peer(Role::P2, std::move(sock2));
    std::cout << "[Party 0] Connected to Party 2" << std::endl;
    
    co_await test_party(Role::P0, net);
    co_return;
}

/**
 * @brief Party 1 (connects to P0, receives from P2)
 */
awaitable<void> party1_main(io_context& io) {
    std::cout << "[Party 1] Starting..." << std::endl;
    
    // Brief delay to let P0 start listening
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    NetContext net(Role::P1);
    
    // Connect to P0
    auto sock0 = co_await make_client(io, "127.0.0.1", BASE_PORT + 1);
    net.add_peer(Role::P0, std::move(sock0));
    std::cout << "[Party 1] Connected to Party 0" << std::endl;
    
    // Accept connection from P2
    auto sock2 = co_await make_server(io, BASE_PORT + 3);
    net.add_peer(Role::P2, std::move(sock2));
    std::cout << "[Party 1] Connected to Party 2" << std::endl;
    
    co_await test_party(Role::P1, net);
    co_return;
}

/**
 * @brief Party 2 (connects to both P0 and P1)
 */
awaitable<void> party2_main(io_context& io) {
    std::cout << "[Party 2] Starting..." << std::endl;
    
    // Brief delay to let others start listening
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    NetContext net(Role::P2);
    
    // Connect to P0
    auto sock0 = co_await make_client(io, "127.0.0.1", BASE_PORT + 2);
    net.add_peer(Role::P0, std::move(sock0));
    std::cout << "[Party 2] Connected to Party 0" << std::endl;
    
    // Connect to P1
    auto sock1 = co_await make_client(io, "127.0.0.1", BASE_PORT + 3);
    net.add_peer(Role::P1, std::move(sock1));
    std::cout << "[Party 2] Connected to Party 1" << std::endl;
    
    co_await test_party(Role::P2, net);
    co_return;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <party_id>\n";
        std::cerr << "  party_id: 0, 1, or 2\n";
        return 1;
    }
    
    int party_id = std::stoi(argv[1]);
    if (party_id < 0 || party_id > 2) {
        std::cerr << "Party ID must be 0, 1, or 2\n";
        return 1;
    }
    
    try {
        io_context io;
        
        if (party_id == 0) {
            co_spawn(io, party0_main(io), detached);
        } else if (party_id == 1) {
            co_spawn(io, party1_main(io), detached);
        } else {
            co_spawn(io, party2_main(io), detached);
        }
        
        io.run();
        
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}