"""The lattice relations in Construction 7.1, before encryption and NIZK."""

from dataclasses import dataclass
from hashlib import shake_256
from math import isfinite, isqrt
from random import SystemRandom

from .linalg import (
    Matrix,
    Vector,
    add_mod,
    has_full_row_rank,
    matvec,
    random_matrix,
    squared_norm,
    sub_mod,
)
from .sampling import sample_bonsai_preimage, sample_vector


@dataclass(frozen=True)
class Parameters:
    n: int = 2
    m: int = 8
    q: int = 17
    s: float = 8
    delta_bytes: int = 16

    def __post_init__(self):
        for name in ("n", "m", "q", "delta_bytes"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.n > self.m:
            raise ValueError("the signer matrix needs n <= m")
        if self.q < 2 or any(self.q % d == 0 for d in range(2, isqrt(self.q) + 1)):
            raise ValueError("q must be prime")
        if not isfinite(self.s) or self.s <= 0:
            raise ValueError("s must be finite and positive")


@dataclass(frozen=True)
class PublicParameters:
    params: Parameters
    A: Matrix
    B: Matrix

    def __post_init__(self):
        _check_matrix(self.A, self.params)
        _check_matrix(self.B, self.params)


@dataclass(frozen=True)
class ReceiverSecret:
    x: Vector
    delta: bytes


@dataclass(frozen=True)
class Presignature:
    z: Vector
    y: Vector


@dataclass(frozen=True)
class Message:
    w: Vector
    delta: bytes


def _check_matrix(matrix: Matrix, params: Parameters) -> None:
    if len(matrix) != params.n or any(len(row) != 2 * params.m for row in matrix):
        raise ValueError("expected an n by 2m matrix")
    if any(type(value) is not int for row in matrix for value in row):
        raise ValueError("matrix entries must be integers")


def _is_vector(vector: Vector, length: int) -> bool:
    return len(vector) == length and all(type(value) is int for value in vector)


def hash_to_syndrome(delta: bytes, n: int, q: int) -> Vector:
    """Map a receiver salt to Z_q^n without reduction bias."""
    if not isinstance(delta, bytes) or type(n) is not int or n <= 0:
        raise ValueError("expected a byte string and a positive dimension")
    if type(q) is not int or q < 2:
        raise ValueError("q must be an integer >= 2")
    domain = b"nibs-section7.1/syndrome/v1\x00" + f"{n}:{q}:".encode("ascii")
    xof = shake_256(domain + delta)
    width = (q.bit_length() + 7) // 8
    limit = (1 << (8 * width)) // q * q
    stream = xof.digest(max(64, n * width * 2))
    offset = 0
    result = []
    while len(result) < n:
        if offset + width > len(stream):
            stream = xof.digest(max(len(stream) * 2, offset + width))
        word = int.from_bytes(stream[offset : offset + width], "big")
        offset += width
        if word < limit:
            result.append(word % q)
    return tuple(result)


def setup(params=None, rng=None) -> PublicParameters:
    """Sample A and B. This does not set up encryption or a proof system."""
    params = params if params is not None else Parameters()
    rng = rng if rng is not None else SystemRandom()
    return PublicParameters(
        params,
        random_matrix(params.n, 2 * params.m, params.q, rng),
        random_matrix(params.n, 2 * params.m, params.q, rng),
    )


def receiver_keygen(pp: PublicParameters, rng=None) -> tuple[ReceiverSecret, Vector]:
    """Return (x, delta) and t = Ax + H(delta)."""
    rng = rng if rng is not None else SystemRandom()
    p = pp.params
    x = sample_vector(2 * p.m, p.s / p.m, rng)
    if squared_norm(x) > 2 * p.s**2 / p.m:
        raise RuntimeError("receiver sample exceeds the norm bound; try again")
    delta = bytes(rng.randrange(256) for _ in range(p.delta_bytes))
    public = add_mod(matvec(pp.A, x, p.q), hash_to_syndrome(delta, p.n, p.q), p.q)
    return ReceiverSecret(x, delta), public


def sample_signer_matrix(pp: PublicParameters, rng=None) -> Matrix:
    """Sample C for the small-parameter experiment, without a trapdoor."""
    rng = rng if rng is not None else SystemRandom()
    p = pp.params
    for _ in range(100):
        matrix = random_matrix(p.n, 2 * p.m, p.q, rng)
        if has_full_row_rank(tuple(row[: p.m] for row in matrix), p.q):
            return matrix
    raise RuntimeError("could not sample a full-rank left block")


def issue_presignature(
    pp: PublicParameters,
    C: Matrix,
    receiver_public: Vector,
    rng=None,
    max_attempts: int = 100_000,
) -> Presignature:
    """Use rejection sampling to find z with Cz + By = t at toy sizes."""
    rng = rng if rng is not None else SystemRandom()
    p = pp.params
    _check_matrix(C, p)
    if not _is_vector(receiver_public, p.n):
        raise ValueError("receiver public key must be an integer n-vector")
    y = tuple(1 if rng.randrange(2) else -1 for _ in range(2 * p.m))
    target = sub_mod(receiver_public, matvec(pp.B, y, p.q), p.q)
    z = sample_bonsai_preimage(C, target, p.q, p.s, rng, max_attempts)
    if squared_norm(z) > 2 * p.m * p.s**2:
        raise RuntimeError("presignature sample exceeds the norm bound; try again")
    return Presignature(z, y)


def check_presignature(
    pp: PublicParameters, C: Matrix, receiver: ReceiverSecret, presignature: Presignature
) -> bool:
    """Check the receiver's lattice conditions, not a final NIBS signature."""
    p = pp.params
    try:
        _check_matrix(C, p)
        if not _is_vector(receiver.x, 2 * p.m):
            return False
        if not isinstance(receiver.delta, bytes) or len(receiver.delta) != p.delta_bytes:
            return False
        if not _is_vector(presignature.z, 2 * p.m):
            return False
        if not _is_vector(presignature.y, 2 * p.m):
            return False
        if any(value not in (-1, 1) for value in presignature.y):
            return False
        if squared_norm(receiver.x) > 2 * p.s**2 / p.m:
            return False
        if squared_norm(presignature.z) > 2 * p.m * p.s**2:
            return False
        left = add_mod(
            matvec(C, presignature.z, p.q), matvec(pp.B, presignature.y, p.q), p.q
        )
        right = add_mod(
            matvec(pp.A, receiver.x, p.q),
            hash_to_syndrome(receiver.delta, p.n, p.q),
            p.q,
        )
        return left == right
    except (ValueError, TypeError):
        return False


def derive_message(
    pp: PublicParameters, C: Matrix, receiver: ReceiverSecret, presignature: Presignature
) -> Message:
    """Compute (w, delta); both x and z contribute their bottom halves."""
    if not check_presignature(pp, C, receiver, presignature):
        raise ValueError("presignature does not match the receiver or norm bounds")
    p = pp.params
    combined = receiver.x[p.m :] + presignature.z[p.m :]
    return Message(matvec(pp.A, combined, p.q), receiver.delta)
