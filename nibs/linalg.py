"""Small integer matrices used by the protocol examples."""

Vector = tuple[int, ...]
Matrix = tuple[Vector, ...]


def _check_modulus(q: int) -> None:
    if not isinstance(q, int) or isinstance(q, bool) or q < 2:
        raise ValueError("q must be an integer at least 2")


def _dimensions(matrix: Matrix) -> tuple[int, int]:
    if not matrix or not matrix[0]:
        raise ValueError("matrix must have at least one row and one column")
    width = len(matrix[0])
    if any(len(row) != width for row in matrix):
        raise ValueError("matrix must be rectangular")
    if any(not isinstance(x, int) for row in matrix for x in row):
        raise ValueError("matrix entries must be integers")
    return len(matrix), width


def matvec(matrix: Matrix, vector: Vector, q: int) -> Vector:
    _check_modulus(q)
    _, width = _dimensions(matrix)
    if len(vector) != width:
        raise ValueError("matrix and vector dimensions do not match")
    return tuple(sum(a * b for a, b in zip(row, vector)) % q for row in matrix)


def add_mod(left: Vector, right: Vector, q: int) -> Vector:
    _check_modulus(q)
    if len(left) != len(right):
        raise ValueError("vector dimensions do not match")
    return tuple((a + b) % q for a, b in zip(left, right))


def sub_mod(left: Vector, right: Vector, q: int) -> Vector:
    _check_modulus(q)
    if len(left) != len(right):
        raise ValueError("vector dimensions do not match")
    return tuple((a - b) % q for a, b in zip(left, right))


def squared_norm(vector: Vector) -> int:
    return sum(x * x for x in vector)


def has_full_row_rank(matrix: Matrix, q: int) -> bool:
    """Return whether the rows are independent over F_q; q must be prime."""
    _check_modulus(q)
    height, width = _dimensions(matrix)
    if height > width:
        return False

    rows = [[x % q for x in row] for row in matrix]
    rank = 0
    for column in range(width):
        pivot = next((i for i in range(rank, height) if rows[i][column]), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        inverse = pow(rows[rank][column], -1, q)
        rows[rank] = [(x * inverse) % q for x in rows[rank]]
        for i in range(rank + 1, height):
            factor = rows[i][column]
            rows[i] = [(a - factor * b) % q for a, b in zip(rows[i], rows[rank])]
        rank += 1
        if rank == height:
            return True
    return False


def random_matrix(rows: int, cols: int, q: int, rng) -> Matrix:
    _check_modulus(q)
    if any(not isinstance(d, int) or isinstance(d, bool) or d < 1 for d in (rows, cols)):
        raise ValueError("matrix dimensions must be positive integers")
    return tuple(tuple(rng.randrange(q) for _ in range(cols)) for _ in range(rows))
