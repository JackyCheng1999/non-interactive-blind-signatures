"""Finite Gaussian sampling and a deliberately slow Bonsai preimage sampler."""

from bisect import bisect_right
from math import ceil, exp, isfinite, pi

from .linalg import Matrix, Vector, _check_modulus, _dimensions, has_full_row_rank, matvec, sub_mod


class DiscreteGaussian:
    """Sample with weight exp(-pi*k^2/s^2), truncated at ceil(8*s)."""

    def __init__(self, s: float):
        try:
            s = float(s)
        except (TypeError, ValueError, OverflowError) as error:
            raise ValueError("s must be finite and positive") from error
        if not isfinite(s) or s <= 0:
            raise ValueError("s must be finite and positive")
        self.s = s
        self.radius = ceil(8 * s)
        weights = [exp(-pi * (k / s) * (k / s)) for k in range(-self.radius, self.radius + 1)]
        total = sum(weights)
        running = 0.0
        cdf = []
        for weight in weights:
            running += weight
            cdf.append(running / total)
        cdf[-1] = 1.0
        self._cdf = tuple(cdf)

    def sample(self, rng) -> int:
        return bisect_right(self._cdf, rng.random()) - self.radius


def sample_vector(length: int, s: float, rng) -> Vector:
    if not isinstance(length, int) or isinstance(length, bool) or length < 0:
        raise ValueError("vector length must be a nonnegative integer")
    gaussian = DiscreteGaussian(s)
    return tuple(gaussian.sample(rng) for _ in range(length))


def sample_bonsai_preimage(
    C: Matrix,
    target: Vector,
    q: int,
    s: float,
    rng,
    max_attempts: int = 100_000,
) -> Vector:
    """Draw the bottom first, then reject top halves until C*x = target mod q.

    This is an executable specification for tiny parameters, not a trapdoor
    sampler. A nearly uniform syndrome needs about q**len(target) attempts.
    """
    _check_modulus(q)
    height, width = _dimensions(C)
    if width % 2:
        raise ValueError("C must have an even number of columns")
    if len(target) != height:
        raise ValueError("target dimension must equal the number of rows of C")
    if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or max_attempts < 1:
        raise ValueError("max_attempts must be a positive integer")

    m = width // 2
    left = tuple(row[:m] for row in C)
    right = tuple(row[m:] for row in C)
    if not has_full_row_rank(left, q):
        raise ValueError("the left half of C must have full row rank modulo q")
    gaussian = DiscreteGaussian(s)
    bottom = tuple(gaussian.sample(rng) for _ in range(m))
    residual = sub_mod(target, matvec(right, bottom, q), q)
    for _ in range(max_attempts):
        top = tuple(gaussian.sample(rng) for _ in range(m))
        if matvec(left, top, q) == residual:
            return top + bottom
    raise RuntimeError(f"preimage sampling exhausted {max_attempts} attempts")
