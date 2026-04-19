#pragma once

#include <cstdint>
#include <stdexcept>
#include <vector>

#include "shares_local.hpp"

/*
 * Local stand-ins for MPC primitives.
 *
 * These functions model the *interface role* of MPC subroutines
 *   - add/sub over additive shares are local and faithful
 *   - multiplication reconstructs inputs locally, multiplies in plaintext,
 *     then re-shares the result
 *   - eqz reconstructs locally and returns an XOR-shared bit
 *   - xor-share bit to additive-share bit conversion reconstructs locally and
 *     re-shares as additive
 *
 * We basically assume secure implementations of these subroutines and hence call these "dummy" functions
 * to illustrate the validity of this protocol.
 */

namespace local_mpc
{

    template <typename T>
    inline AdditiveShare<T> public_additive(T value)
    {
        return AdditiveShare<T>(value, 0);
    }

    template <typename T>
    inline XorShare<T> public_xor(T value)
    {
        return XorShare<T>(value, 0);
    }

    template <typename T>
    inline AdditiveShare<T> mpc_mul(const AdditiveShare<T> &a, const AdditiveShare<T> &b)
    {
        static_assert(std::is_integral_v<T>, "mpc_mul requires integral type");

        // Beaver triple: [u], [v], [w] where w = u * v
        T u_plain = static_cast<T>(random_u64());
        T v_plain = static_cast<T>(random_u64());
        T w_plain = static_cast<T>(u_plain * v_plain);

        AdditiveShare<T> u = share_secret_additive<T>(u_plain);
        AdditiveShare<T> v = share_secret_additive<T>(v_plain);
        AdditiveShare<T> w = share_secret_additive<T>(w_plain);

        // Compute masked differences
        AdditiveShare<T> d_share = a - u;
        AdditiveShare<T> e_share = b - v;

        // Open only the masked values d = a-u and e = b-v
        // In this local model, opening is simulated by reconstruction.
        T d = reconstruct(d_share);
        T e = reconstruct(e_share);

        // Multiply a share by a public constant
        AdditiveShare<T> dv(
            static_cast<T>(d * v.left),
            static_cast<T>(d * v.right));

        AdditiveShare<T> eu(
            static_cast<T>(e * u.left),
            static_cast<T>(e * u.right));

        // Public value d*e represented as an additive share
        AdditiveShare<T> de(
            static_cast<T>(d * e),
            static_cast<T>(0));

        // [ab] = [w] + d[v] + e[u] + de
        return w + dv + eu + de;
    }

    template <typename T>
    inline XorShare<T> mpc_and(const XorShare<T> &a, const XorShare<T> &b)
    {
        T plain = static_cast<T>(reconstruct(a) & reconstruct(b));
        return share_secret_xor<T>(plain);
    }

    template <typename T>
    inline XorShare<T> mpc_or(const XorShare<T> &a, const XorShare<T> &b)
    {
        T plain = static_cast<T>(reconstruct(a) | reconstruct(b));
        return share_secret_xor<T>(plain);
    }

    template <typename T>
    inline XorShare<T> mpc_eqz(const AdditiveShare<T> &a)
    {
        T plain = reconstruct(a);
        T out = (plain == 0) ? static_cast<T>(1) : static_cast<T>(0);
        return share_secret_xor<T>(out);
    }

    template <typename T>
    inline AdditiveShare<T> xshare_bit_to_ashare(const XorShare<T> &x)
    {
        T plain = reconstruct(x);
        if (plain != 0 && plain != 1)
        {
            throw std::runtime_error("xshare_bit_to_ashare expects a bit share");
        }
        return share_secret_additive<T>(plain);
    }

    template <typename T>
    inline AdditiveShare<T> operator*(const AdditiveShare<T> &a, const AdditiveShare<T> &b)
    {
        return mpc_mul(a, b);
    }

    template <typename T>
    inline XorShare<T> operator*(const XorShare<T> &a, const XorShare<T> &b)
    {
        return mpc_and(a, b);
    }

    template <typename T>
    inline XorShare<T> operator|(const XorShare<T> &a, const XorShare<T> &b)
    {
        return mpc_or(a, b);
    }

    template <typename T>
    inline XorShare<T> operator==(const AdditiveShare<T> &a, T zero)
    {
        if (zero != 0)
        {
            throw std::runtime_error("Only equality to zero is supported");
        }
        return mpc_eqz(a);
    }

    template <typename T>
    inline AdditiveShare<T> multiply_by_public(const AdditiveShare<T> &a, uint64_t c)
    {
        AdditiveShare<T> out = public_additive<T>(0);
        for (uint64_t i = 0; i < c; ++i)
        {
            out += a;
        }
        return out;
    }

} // namespace local_mpc
