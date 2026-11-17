"""Generate and publicly verify an L2 proof with the real LaZer backend."""

import argparse
from dataclasses import replace
from random import Random, SystemRandom
import secrets
from time import perf_counter

from .nizk import LazerNIZK
from .protocol import issue_presignature, receiver_keygen, sample_signer_matrix, setup
from .regev import decrypt, keygen
from .signatures import obtain, verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, help="reproduce the toy keys and issuance")
    args = parser.parse_args()
    rng = Random(args.seed) if args.seed is not None else SystemRandom()
    pp = setup(rng=rng)
    C = sample_signer_matrix(pp, rng)
    receiver, public = receiver_keygen(pp, rng)
    presignature = issue_presignature(pp, C, public, rng)
    encryption_key, decryption_key = keygen(rng=rng)
    crs_seed = secrets.token_bytes(32)
    prover = LazerNIZK(crs_seed)

    started = perf_counter()
    message, signature = obtain(pp, C, receiver, presignature, encryption_key, prover, rng)
    prove_seconds = perf_counter() - started
    # Public verification starts with a fresh object and has no receiver secret.
    verifier = LazerNIZK(crs_seed)
    started = perf_counter()
    accepted = verify(pp, C, encryption_key, message, signature, verifier)
    verify_seconds = perf_counter() - started
    expected = receiver.x + presignature.y + presignature.z
    recovered = decrypt(decryption_key, signature.ciphertext)
    changed = replace(message, w=((message.w[0] + 1) % pp.params.q,) + message.w[1:])
    tampered = verify(pp, C, encryption_key, changed, signature, verifier)

    print("L2 proof with LaZer / LNP22 (toy NIBS and encryption parameters)")
    print(f"proof bytes: {len(signature.proof)}")
    print(f"prove: {prove_seconds:.3f} s")
    print(f"verify, including worker: {verify_seconds:.3f} s")
    print(f"public verification: {accepted}")
    print(f"encrypted witness recovered: {recovered == expected}")
    print(f"modified message rejected: {not tampered}")
    if not accepted or recovered != expected or tampered:
        raise RuntimeError("the L2 integration check failed")


if __name__ == "__main__":
    main()
