"""Regev-style encryption of short signed integer vectors.

The defaults keep the witness-encryption demo small. They are not secure
parameters; each coordinate uses a separate subset of the public samples.
"""

from dataclasses import dataclass
from math import isqrt
from random import SystemRandom

from .linalg import Matrix, Vector


@dataclass(frozen=True)
class Params:
    dimension: int = 4
    samples: int = 8
    q: int = 65537
    scale: int = 512
    plaintext_bound: int = 63
    error_bound: int = 1

    def __post_init__(self):
        for name in ("dimension", "samples", "q", "scale", "plaintext_bound"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if type(self.error_bound) is not int or self.error_bound < 0:
            raise ValueError("error_bound must be a nonnegative integer")
        if self.q < 2 or any(self.q % d == 0 for d in range(2, isqrt(self.q) + 1)):
            raise ValueError("q must be prime")
        noise = self.samples * self.error_bound
        if 2 * noise >= self.scale:
            raise ValueError("the noise bound must be less than half the scale")
        if self.q <= 2 * (self.scale * self.plaintext_bound + noise):
            raise ValueError("q is too small for the scaled plaintext and noise")


def _vector(value, name):
    if not isinstance(value, (tuple, list)) or any(type(x) is not int for x in value):
        raise ValueError(f"{name} must be an integer vector")
    return tuple(value)


def _rows(value, name):
    if not isinstance(value, (tuple, list)):
        raise ValueError(f"{name} must be a matrix")
    return tuple(_vector(row, name) for row in value)


def _residues(vector, length, q, name):
    if len(vector) != length or any(x < 0 or x >= q for x in vector):
        raise ValueError(f"{name} has invalid dimensions or residues")


def _params(value):
    if not isinstance(value, Params):
        raise ValueError("expected encryption parameters")


@dataclass(frozen=True)
class PublicKey:
    params: Params
    A: Matrix
    b: Vector

    def __post_init__(self):
        _params(self.params)
        A = _rows(self.A, "A")
        b = _vector(self.b, "b")
        if len(A) != self.params.samples:
            raise ValueError("A must have one row per public sample")
        for row in A:
            _residues(row, self.params.dimension, self.params.q, "A")
        _residues(b, self.params.samples, self.params.q, "b")
        object.__setattr__(self, "A", A)
        object.__setattr__(self, "b", b)


@dataclass(frozen=True)
class SecretKey:
    params: Params
    s: Vector

    def __post_init__(self):
        _params(self.params)
        s = _vector(self.s, "s")
        _residues(s, self.params.dimension, self.params.q, "s")
        object.__setattr__(self, "s", s)


@dataclass(frozen=True)
class Ciphertext:
    u: tuple[Vector, ...]
    v: Vector

    def __post_init__(self):
        u = _rows(self.u, "u")
        v = _vector(self.v, "v")
        if not v or len(u) != len(v):
            raise ValueError("ciphertext must have equally many u rows and v entries")
        object.__setattr__(self, "u", u)
        object.__setattr__(self, "v", v)


@dataclass(frozen=True)
class EncryptionRandomness:
    rows: tuple[Vector, ...]

    def __post_init__(self):
        rows = _rows(self.rows, "randomness")
        if not rows or any(not row or any(x not in (0, 1) for x in row) for row in rows):
            raise ValueError("encryption randomness must contain binary rows")
        object.__setattr__(self, "rows", rows)


def keygen(params=None, rng=None) -> tuple[PublicKey, SecretKey]:
    params = params if params is not None else Params()
    _params(params)
    rng = rng if rng is not None else SystemRandom()
    A = tuple(
        tuple(rng.randrange(params.q) for _ in range(params.dimension))
        for _ in range(params.samples)
    )
    s = tuple(rng.randrange(params.q) for _ in range(params.dimension))
    errors = tuple(
        rng.randrange(-params.error_bound, params.error_bound + 1)
        for _ in range(params.samples)
    )
    b = tuple(
        (sum(a * x for a, x in zip(row, s)) + e) % params.q
        for row, e in zip(A, errors)
    )
    return PublicKey(params, A, b), SecretKey(params, s)


def encrypt(
    pk: PublicKey, message: Vector, randomness=None, rng=None
) -> tuple[Ciphertext, EncryptionRandomness]:
    """Return a ciphertext and the exact subset choices used to encrypt it."""
    if not isinstance(pk, PublicKey):
        raise ValueError("expected an encryption public key")
    p = pk.params
    message = _vector(message, "message")
    if not message or any(abs(x) > p.plaintext_bound for x in message):
        raise ValueError("message must be nonempty and within the plaintext bound")
    if randomness is None:
        rng = rng if rng is not None else SystemRandom()
        randomness = EncryptionRandomness(
            tuple(tuple(rng.randrange(2) for _ in range(p.samples)) for _ in message)
        )
    if not isinstance(randomness, EncryptionRandomness):
        raise ValueError("expected encryption randomness")
    if len(randomness.rows) != len(message) or any(
        len(row) != p.samples for row in randomness.rows
    ):
        raise ValueError("randomness must have one samples-wide row per message entry")

    u = tuple(
        tuple(
            sum(pk.A[i][j] * row[i] for i in range(p.samples)) % p.q
            for j in range(p.dimension)
        )
        for row in randomness.rows
    )
    v = tuple(
        (sum(b * r for b, r in zip(pk.b, row)) + p.scale * m) % p.q
        for row, m in zip(randomness.rows, message)
    )
    return Ciphertext(u, v), randomness


def decrypt(sk: SecretKey, ciphertext: Ciphertext) -> Vector:
    """Decode each coordinate; malformed inputs can fail, but this is not authentication."""
    if not isinstance(sk, SecretKey) or not isinstance(ciphertext, Ciphertext):
        raise ValueError("expected a secret key and ciphertext")
    p = sk.params
    _residues(ciphertext.v, len(ciphertext.u), p.q, "v")
    result = []
    for u, v in zip(ciphertext.u, ciphertext.v):
        _residues(u, p.dimension, p.q, "u")
        phase = (v - sum(a * b for a, b in zip(u, sk.s))) % p.q
        if phase > p.q // 2:
            phase -= p.q
        decoded = (abs(phase) + p.scale // 2) // p.scale
        if phase < 0:
            decoded = -decoded
        if abs(decoded) > p.plaintext_bound:
            raise ValueError("decoded plaintext exceeds its bound")
        if abs(phase - p.scale * decoded) > p.samples * p.error_bound:
            raise ValueError("ciphertext residual exceeds the noise bound")
        result.append(decoded)
    return tuple(result)
