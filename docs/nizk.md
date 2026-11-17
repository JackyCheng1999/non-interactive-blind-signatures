# LNP proof of the witness relation

The backend uses [LaZer](https://github.com/lazer-crypto/lazer) at commit
`10eafeca4cd53ff4fc54193dce904dbd0026fefd`, the CCS 2024 artifact revision.
It calls the library's [LNP22](https://eprint.iacr.org/2022/284) prover and verifier. No receiver secret or
encryption randomness is passed to verification.

## Build and run

The tested setup is macOS on ARM64, with Clang, GMP, MPFR, and Python 3.9.
The build script also has a Linux x86-64 path using upstream's build process;
that path has not been run here. The ARM patch selects existing generic C and
HEXL routines and disables x86-specific dispatch. It does not change the proof
equations. LaBRADOR is not built.

Start in the repository root:

```sh
python3 -m venv .deps/venv
.deps/venv/bin/python -m pip install -r requirements-lazer.txt
PYTHON=.deps/venv/bin/python scripts/build_lazer.sh
.deps/venv/bin/python scripts/build_nizk_params.py
.deps/venv/bin/python -m nibs.nizk_demo --seed 7
NIBS_RUN_LAZER_TESTS=1 .deps/venv/bin/python -m unittest discover -s tests -v
```

The build needs GMP and MPFR headers and libraries. On ARM macOS the script
looks for their Homebrew prefixes. Set `GMP_PREFIX` and `MPFR_PREFIX` when they
are elsewhere. The source, Python environment, and compiled modules stay in
`.deps/`, which is ignored by Git.

The checked-in parameter header is enough to build the example. To regenerate
it, use SageMath 10.2 or newer:

```sh
.deps/venv/bin/python scripts/build_nizk_params.py --sage /path/to/sage
```

The parameter source is `proofs/l2_params.py`. The current compiled profile
supports the default `protocol.Parameters()` and `regev.Params()` only.
Other parameters are rejected rather than silently using incompatible bounds.

## Encoding

Let $L=2m=16$. The scalar witness is

$$
W=(x,z,b_y,r_0,\ldots,r_{47}),\qquad y=2b_y-1.
$$

There are 432 scalar coordinates. The first two groups have squared norm bounds
$16$ and $1024$. All remaining coordinates are binary. The native parameter
header contains exactly these two squared bounds and 400 binary slots.

For each coordinate $a_j$ of $x\|y\|z$, the Regev-style encryption uses
independent binary randomness $r_j$:

$$
u_j=A_E^T r_j\pmod Q,\qquad
v_j=b_E^T r_j+512a_j\pmod Q,\qquad Q=65537.
$$

The core equations use $q=17$. We put both sets of equations into modulus
$P=\operatorname{lcm}(q,Q)=1114129$: multiply core rows by $P/q$ and
encryption rows by $P/Q$. Each scaled equation is equivalent to its original
congruence. This avoids treating the two moduli as interchangeable.

The resulting 244 rows enforce:

- $-Ax+Cz+2Bb_y=H(\delta)+B\mathbf1$;
- $A_Lx_b+A_Rz_b=w$;
- all $u_j$ equations;
- all $v_j$ equations, using these same $x,z,b_y$ coordinates.

For a nonce coordinate the last equation is
$b_E^T r_j+1024b_{y,j}=v_j+512$.

Each scalar occupies the constant coefficient of a degree-64 polynomial.
All public matrix entries are also constant polynomials. Projecting any valid
polynomial witness onto its constant coefficients preserves every scalar
equation, binary constraint, and norm bound. The larger polynomial space
increases the cost of this first implementation.

## Context and proof input

The adapter derives LaZer's public state seed from a global 32-byte CRS seed,
the pinned backend version, and the canonical complete public statement. In
particular, the raw receiver salt is included, in addition to $H(\delta)$.
This follows the message-binding use of the state seed in LaZer's CBDC example.
It is an explicit adapter choice; this project has not established a new
security theorem for that choice.

The native decoder has no input-length parameter. Verification runs in a
separate worker, appends alternating guard bits, and requires the decoder to
consume exactly the original proof length. Invalid inputs, worker failures,
and timeouts are rejected. The adapter caps input proofs at 1 MiB.

## Current limits

The core and encryption parameters are small demonstration parameters. Issuance
still uses the public rejection sampler. The encryption is a scalar Regev-style
instance, rather than the ring-based concrete instantiation in Section 7.4.
This gives an executable $L_2$ proof and obtain/verify path, not a deployment
parameter set or a reproduction of the paper's signature-size estimate.

One local ARM64 run produced a 91,160-byte proof in 106.7 seconds; public
verification, including the worker, took 58.5 seconds. These timings describe
the generic build and the scalar encoding above. They are not cryptographic
security estimates.
