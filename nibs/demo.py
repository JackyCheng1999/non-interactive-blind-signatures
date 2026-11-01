"""Run the Section 7.1 lattice core with small parameters."""

import argparse
from dataclasses import replace
from random import Random, SystemRandom

from .protocol import (
    check_presignature,
    derive_message,
    issue_presignature,
    receiver_keygen,
    sample_signer_matrix,
    setup,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, help="use reproducible randomness for this experiment")
    args = parser.parse_args()
    rng = Random(args.seed) if args.seed is not None else SystemRandom()

    pp = setup(rng=rng)
    C = sample_signer_matrix(pp, rng)
    secret, public = receiver_keygen(pp, rng)
    p = pp.params
    print(f"Section 7.1 lattice core (toy n={p.n}, m={p.m}, q={p.q}, s={p.s})")
    print(f"receiver public key: {public}")
    for index in (1, 2):
        presignature = issue_presignature(pp, C, public, rng)
        message = derive_message(pp, C, secret, presignature)
        print(f"issuance {index}: presignature accepted, w={message.w}")

    # Change a coordinate that actually changes the syndrome.
    column = next(j for j in range(2 * p.m) if any(row[j] % p.q for row in C))
    changed = list(presignature.z)
    changed[column] += 1
    tampered = replace(presignature, z=tuple(changed))
    rejected = not check_presignature(pp, C, secret, tampered)
    print(f"tampered presignature rejected: {rejected}")
    if not rejected:
        raise RuntimeError("the tampering check failed")


if __name__ == "__main__":
    main()
