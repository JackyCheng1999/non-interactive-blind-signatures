"""Encode the Section 7.1 witness relation as one modular linear system."""

from dataclasses import asdict, dataclass
from fractions import Fraction
import json
from math import lcm

from .linalg import Matrix, Vector, squared_norm
from .protocol import Message, Presignature, PublicParameters, ReceiverSecret, hash_to_syndrome
from .regev import Ciphertext, EncryptionRandomness, PublicKey


@dataclass(frozen=True)
class Statement:
    pp: PublicParameters
    C: Matrix
    encryption_key: PublicKey
    message: Message
    ciphertext: Ciphertext


@dataclass(frozen=True)
class Witness:
    receiver: ReceiverSecret
    presignature: Presignature
    randomness: EncryptionRandomness


@dataclass(frozen=True)
class LinearSystem:
    modulus: int
    matrix: Matrix
    rhs: Vector
    width: int
    receiver_bound_squared: int
    presignature_bound_squared: int

    @property
    def columns(self):
        return len(self.matrix[0])


def _integers(values, length, name):
    if len(values) != length or any(type(x) is not int for x in values):
        raise ValueError(f"invalid {name}")


def _validate(statement):
    p = statement.pp.params
    ep = statement.encryption_key.params
    width = 2 * p.m
    if len(statement.C) != p.n:
        raise ValueError("invalid signer matrix")
    for matrix in (statement.pp.A, statement.pp.B, statement.C):
        if len(matrix) != p.n:
            raise ValueError("invalid matrix height")
        for row in matrix:
            _integers(row, width, "matrix row")
            if any(not 0 <= value < p.q for value in row):
                raise ValueError("matrix entries must be canonical residues")
    _integers(statement.message.w, p.n, "message vector")
    if any(not 0 <= value < p.q for value in statement.message.w):
        raise ValueError("message entries must be canonical residues")
    if not isinstance(statement.message.delta, bytes) or len(statement.message.delta) != p.delta_bytes:
        raise ValueError("invalid receiver salt")
    ct = statement.ciphertext
    _integers(ct.v, 3 * width, "ciphertext vector")
    if len(ct.u) != 3 * width or any(not 0 <= value < ep.q for value in ct.v):
        raise ValueError("invalid ciphertext dimensions or residues")
    for row in ct.u:
        _integers(row, ep.dimension, "ciphertext row")
        if any(not 0 <= value < ep.q for value in row):
            raise ValueError("ciphertext entries must be canonical residues")


def encode_statement(statement: Statement) -> LinearSystem:
    _validate(statement)
    p = statement.pp.params
    pk = statement.encryption_key
    ep = pk.params
    width = 2 * p.m
    columns = 3 * width + 3 * width * ep.samples
    modulus = lcm(p.q, ep.q)
    core_scale, enc_scale = modulus // p.q, modulus // ep.q
    matrix, rhs = [], []

    def equation(coefficients, value, scale):
        row = [0] * columns
        for index, coefficient in coefficients.items():
            row[index] = coefficient * scale % modulus
        matrix.append(tuple(row))
        rhs.append(value * scale % modulus)

    # Witness order: x, z, (y+1)/2, then one binary r_j per encrypted coordinate.
    h = hash_to_syndrome(statement.message.delta, p.n, p.q)
    for a, b, c, digest in zip(statement.pp.A, statement.pp.B, statement.C, h):
        coefficients = {i: -a[i] for i in range(width)}
        coefficients.update({width + i: c[i] for i in range(width)})
        coefficients.update({2 * width + i: 2 * b[i] for i in range(width)})
        equation(coefficients, digest + sum(b), core_scale)

    for a, value in zip(statement.pp.A, statement.message.w):
        coefficients = {p.m + i: a[i] for i in range(p.m)}
        coefficients.update({width + p.m + i: a[p.m + i] for i in range(p.m)})
        equation(coefficients, value, core_scale)

    # Regev ciphertexts encrypt x || y || z using the same hidden coordinates.
    for j, (u, v) in enumerate(zip(statement.ciphertext.u, statement.ciphertext.v)):
        start = 3 * width + j * ep.samples
        for coordinate, value in enumerate(u):
            equation(
                {start + i: pk.A[i][coordinate] for i in range(ep.samples)},
                value,
                enc_scale,
            )
        coefficients = {start + i: pk.b[i] for i in range(ep.samples)}
        if j < width:
            coefficients[j] = ep.scale
        elif j < 2 * width:
            coefficients[2 * width + j - width] = 2 * ep.scale
            v += ep.scale
        else:
            coefficients[width + j - 2 * width] = ep.scale
        equation(coefficients, v, enc_scale)

    s = Fraction(str(p.s))
    x_bound = int(2 * s * s / p.m)
    z_bound = int(2 * p.m * s * s)
    if ep.plaintext_bound**2 < max(x_bound, z_bound):
        raise ValueError("encryption plaintext range does not cover the witness bounds")
    return LinearSystem(modulus, tuple(matrix), tuple(rhs), width, x_bound, z_bound)


def encode_witness(statement: Statement, witness: Witness) -> Vector:
    width = 2 * statement.pp.params.m
    _integers(witness.receiver.x, width, "receiver secret")
    _integers(witness.presignature.z, width, "presignature")
    _integers(witness.presignature.y, width, "nonce")
    if witness.receiver.delta != statement.message.delta:
        raise ValueError("receiver salt does not match the message")
    if any(y not in (-1, 1) for y in witness.presignature.y):
        raise ValueError("nonce must contain signs")
    randomness = witness.randomness.rows
    if len(randomness) != 3 * width:
        raise ValueError("invalid encryption randomness height")
    for row in randomness:
        _integers(row, statement.encryption_key.params.samples, "encryption randomness")
        if any(value not in (0, 1) for value in row):
            raise ValueError("encryption randomness must be binary")
    bits = tuple((y + 1) // 2 for y in witness.presignature.y)
    return (
        witness.receiver.x
        + witness.presignature.z
        + bits
        + tuple(value for row in randomness for value in row)
    )


def check_witness(system: LinearSystem, vector: Vector) -> bool:
    width = system.width
    if len(vector) != system.columns or any(type(value) is not int for value in vector):
        return False
    if squared_norm(vector[:width]) > system.receiver_bound_squared:
        return False
    if squared_norm(vector[width : 2 * width]) > system.presignature_bound_squared:
        return False
    if any(value not in (0, 1) for value in vector[2 * width :]):
        return False
    return all(
        sum(a * b for a, b in zip(row, vector)) % system.modulus == target
        for row, target in zip(system.matrix, system.rhs)
    )


def statement_bytes(statement: Statement) -> bytes:
    """Canonical public input used for proof context binding."""
    data = asdict(statement)
    data["message"]["delta"] = statement.message.delta.hex()
    return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def statement_from_dict(data) -> Statement:
    """Read a public statement in the isolated native verifier."""
    from .protocol import Parameters
    from .regev import Params

    pp_data = data["pp"]
    pp = PublicParameters(
        Parameters(**pp_data["params"]),
        tuple(tuple(row) for row in pp_data["A"]),
        tuple(tuple(row) for row in pp_data["B"]),
    )
    key = data["encryption_key"]
    pk = PublicKey(Params(**key["params"]), key["A"], key["b"])
    message = Message(tuple(data["message"]["w"]), bytes.fromhex(data["message"]["delta"]))
    ciphertext = Ciphertext(data["ciphertext"]["u"], data["ciphertext"]["v"])
    return Statement(pp, tuple(tuple(row) for row in data["C"]), pk, message, ciphertext)
