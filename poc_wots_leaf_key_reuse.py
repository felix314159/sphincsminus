#!/usr/bin/env python3
"""Regression PoC: distinct XMSS leaves must not reuse a WOTS key."""

from sphincs_minus import (
    DEFAULT_PARAMS,
    WOTS_HASH,
    make_adrs,
    sphincs_keygen,
    wotsParams,
    wots_sign,
)


def main() -> None:
    params = DEFAULT_PARAMS
    sk_seed, _, pk_seed, _, _ = sphincs_keygen(params)
    message = b"same WOTS message"
    signatures = []

    for leaf in (0, 1):
        adrs = make_adrs(
            params.d - 1, 0, WOTS_HASH, kp_addr=leaf
        )
        signatures.append(
            wots_sign(
                params.n, params.w, pk_seed, sk_seed, adrs, message
            )
        )

    if signatures[0] == signatures[1]:
        raise AssertionError("VULNERABLE: XMSS leaves reuse one WOTS key")

    expected_chains = wotsParams(params.n, params.w)["l"]
    assert len(signatures[0]) == len(signatures[1]) == expected_chains
    print("PASS: WOTS keys are domain-separated by XMSS leaf address")


if __name__ == "__main__":
    main()
