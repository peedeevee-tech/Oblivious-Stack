## Oblivious Stack over Secret Shares (MPC Prototype)

This project implements an oblivious stack using secret-sharing techniques inspired by Multi-Party Computation (MPC).

The goal is to demonstrate how stack operations can be executed while hiding:

- operation type (push vs pop)
- stack size
- memory access patterns

## Key Idea

All operations are expressed as a unified arithmetic circuit over secret shares:

- every index is updated in every operation
- no data-dependent branching
- access patterns remain constant

## Components

Additive Shares: x = (x0 + x1) mod 2^64
XOR Shares: for boolean values
Unified Operation: handles push and pop together

## MPC-Style Primitives

Addition / subtraction (local)
Multiplication via Beaver-triple style protocol
Equality-to-zero (modeled locally)
XOR → additive conversion

## Note

This is a local simulation, not a full MPC system:

- no networking or communication
- no real distributed parties
- designed for protocol validation and understanding

## Files

- shares_local.hpp – share representations
- mpcops_local.hpp – MPC-style primitives
- oblivious_stack_shared.hpp – stack logic
- test_oblivious_stack_shared.cpp – tests
- oblivious_queue_shared.hpp – queue logic
- test_oblivious_queue_shared.cpp – tests

## Build & Run

g++ -std=c++17 test_oblivious_stack_shared.cpp -o test
./test

g++ -std=c++17 test_oblivious_queue_shared.cpp -o test2
./test2

## Output

All local secret-share oblivious stack tests passed.

## Future Work

- Distributed MPC with secure communication
- Fully secure equality protocols
- Performance optimizations (e.g., ORAM)

## Summary

A compact prototype showing how data structures can be made oblivious using MPC-style techniques, with clear separation between protocol logic and secure execution.
