# Non-interactive blind signatures

Code for the lattice-based construction in [Non-interactive Blind Signatures:
Post-quantum and Stronger Security](https://eprint.iacr.org/2024/614),
with Foteini Baldimtsi, Rishab Goyal, and Aayush Yadav (ASIACRYPT 2024).

I am starting with the lattice relations in Section 7.1: receiver key generation,
presignature sampling and checks, and the derivation of the message. The code uses
small parameters and rejection sampling so these steps can be checked without a
trapdoor implementation. Encryption and zero-knowledge proofs are not included
yet, so this version does not produce a complete NIBS signature.

## Run

Python 3.9 or later. No external packages are needed. From the repository root:

```sh
python3 -m nibs.demo --seed 7
python3 -m unittest discover -s tests -v
```

The example generates one receiver key and issues two presignatures to it. It
checks each presignature, computes its message, and rejects a modified
presignature. The seed is optional and is only for reproducing the example.

## Code

- `nibs/protocol.py`: the Section 7.1 relations and message derivation.
- `nibs/sampling.py`: a finite discrete Gaussian and small-parameter preimage sampling.
- `nibs/linalg.py`: modular matrix arithmetic.
- `tests/`: arithmetic fixtures, protocol checks, and invalid inputs.

[Construction notes](docs/construction.md) give the equations and explain how the
sampler differs from the paper. The default parameters are `n=2`, `m=8`, `q=17`,
and `s=8`. They are for working through the construction, not for security or
performance comparisons.

Next I plan to add the trapdoor sampler, then encryption and the proof layer.
