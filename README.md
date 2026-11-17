# Non-interactive blind signatures

Code for the lattice-based construction in [Non-interactive Blind Signatures:
Post-quantum and Stronger Security](https://eprint.iacr.org/2024/614),
with Foteini Baldimtsi, Rishab Goyal, and Aayush Yadav (ASIACRYPT 2024).

The current version implements the Section 7.1 relations, encrypts the receiver's
witness, and uses LaZer's LNP22 backend to generate and verify the proof. The
proof ties the presignature, message, nonce bits, norm bounds, and ciphertext to
the same hidden vectors.

I am using small parameters while putting the pieces together. Issuance still
uses rejection sampling without a signing trapdoor, and the Regev encryption
parameters are also small. This is a correctness prototype; a secure parameter
set and the actual trapdoor sampler are still needed.

## Run

Python 3.9 or later. The algebra example and ordinary tests use the standard library:

```sh
python3 -m nibs.demo --seed 7
python3 -m unittest discover -s tests -v
```

The example generates one receiver key and issues two presignatures to it. It
checks each presignature, computes its message, and rejects a modified
presignature. The seed is optional and is only for reproducing the example.

For the real NIZK example, first build the dependencies using the instructions
in [docs/nizk.md](docs/nizk.md), then run:

```sh
.deps/venv/bin/python -m nibs.nizk_demo --seed 7
NIBS_RUN_LAZER_TESTS=1 .deps/venv/bin/python -m unittest discover -s tests -v
```

The example generates a proof, verifies it using only public inputs, checks that
the ciphertext recovers the witness, and rejects a modified message. Proof
randomness comes from the library's system RNG even when `--seed` is set.

## Code

- `nibs/protocol.py`: the Section 7.1 relations and message derivation.
- `nibs/regev.py`: witness encryption and decryption.
- `nibs/l2.py`: the complete relation, including ciphertext consistency.
- `nibs/nizk.py`: the LaZer adapter; `nibs/signatures.py`: obtain and verify.
- `nibs/sampling.py`: a finite discrete Gaussian and small-parameter preimage sampling.
- `nibs/linalg.py`: modular matrix arithmetic.
- `tests/`: arithmetic fixtures, protocol checks, and invalid inputs.

[Construction notes](docs/construction.md) give the equations and explain how the
sampler differs from the paper. The default parameters are `n=2`, `m=8`, `q=17`,
and `s=8`. They are for working through the construction, not for security or
performance comparisons.

LaZer is pinned to its CCS 2024 artifact revision. A small compatibility patch
lets its LNP backend run on Apple Silicon. The native library stays under
`.deps/`; its source and license are attributed in [third_party/NOTICE.md](third_party/NOTICE.md).
