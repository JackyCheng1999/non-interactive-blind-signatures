"""LaZer/LNP22 backend for the fixed small-parameter L2 instance."""

import base64
from hashlib import shake_256
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys

from .l2 import Statement, Witness, check_witness, encode_statement, encode_witness, statement_bytes
from .protocol import Parameters
from .regev import Params

UPSTREAM_COMMIT = "10eafeca4cd53ff4fc54193dce904dbd0026fefd"
MAX_PROOF_BYTES = 1_048_576
VERIFY_TIMEOUT_SECONDS = 180


class BackendUnavailable(RuntimeError):
    pass


def _load_native():
    root = Path(__file__).resolve().parents[1]
    source = Path(os.environ.get("NIBS_LAZER_DIR", root / ".deps" / "lazer"))
    params = Path(os.environ.get("NIBS_LAZER_PARAMS_DIR", root / ".deps" / "nibs-l2"))
    for path in (source / "python", params):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    try:
        lazer = importlib.import_module("lazer")
        module = importlib.import_module("_nibs_l2_params_cffi")
    except (ImportError, OSError) as error:
        raise BackendUnavailable(
            "Build LaZer and the L2 parameter module first; see docs/nizk.md."
        ) from error
    pointer = module.lib.get_params("nibs_l2")
    if pointer == module.ffi.NULL:
        raise BackendUnavailable("the parameter module does not contain nibs_l2")
    return lazer, pointer


def _check_supported_parameters(statement):
    if statement.pp.params != Parameters() or statement.encryption_key.params != Params():
        raise ValueError("this proof profile supports the default demo parameters only")


def _check_profile(system):
    if (
        system.modulus != 1_114_129
        or len(system.matrix) != 244
        or system.columns != 432
        or system.receiver_bound_squared != 16
        or system.presignature_bound_squared != 1024
    ):
        raise ValueError("statement does not match the compiled L2 proof profile")


def _native_statement(lazer, system):
    ring = lazer.polyring_t(64, system.modulus)
    matrix = lazer.polymat_t(ring, len(system.matrix), system.columns)
    for i, row in enumerate(system.matrix):
        for j, coefficient in enumerate(row):
            if coefficient:
                matrix.set_elem(lazer.poly_t(ring, {0: coefficient}), i, j)
    target = lazer.polyvec_t(
        ring, len(system.rhs), [lazer.poly_t(ring, {0: -value}) for value in system.rhs]
    )
    return ring, matrix, target


class LazerNIZK:
    def __init__(self, crs_seed: bytes):
        if not isinstance(crs_seed, bytes) or len(crs_seed) != 32:
            raise ValueError("the public CRS seed must be 32 bytes")
        self.crs_seed = crs_seed

    def _seed(self, statement):
        domain = b"nibs-l2/lnp22/context/v1\x00" + bytes.fromhex(UPSTREAM_COMMIT)
        return shake_256(domain + self.crs_seed + statement_bytes(statement)).digest(32)

    def prove(self, statement: Statement, witness: Witness) -> bytes:
        _check_supported_parameters(statement)
        system = encode_statement(statement)
        _check_profile(system)
        vector = encode_witness(statement, witness)
        if not check_witness(system, vector):
            raise ValueError("witness does not satisfy the full L2 relation")
        lazer, params = _load_native()
        ring, matrix, target = _native_statement(lazer, system)
        native_witness = lazer.polyvec_t(
            ring, len(vector), [lazer.poly_t(ring, {0: value}) for value in vector]
        )
        prover = lazer.lin_prover_state_t(self._seed(statement), params)
        prover.set_statement(matrix, target)
        prover.set_witness(native_witness)
        proof = prover.prove()
        if not isinstance(proof, bytes) or not 32 <= len(proof) <= MAX_PROOF_BYTES:
            raise RuntimeError("unexpected proof encoding from LaZer")
        return proof

    def verify(self, statement: Statement, proof: bytes) -> bool:
        if not isinstance(proof, bytes) or not 32 <= len(proof) <= MAX_PROOF_BYTES:
            return False
        try:
            _check_supported_parameters(statement)
            system = encode_statement(statement)
            _check_profile(system)
            payload = {
                "crs_seed": self.crs_seed.hex(),
                "statement": json.loads(statement_bytes(statement)),
                "proof": base64.b64encode(proof).decode("ascii"),
            }
        except (ValueError, TypeError, AttributeError):
            return False
        # The upstream decoder has no input-length argument. Keep malformed
        # native input in a separate process, and reject crashes and timeouts.
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join(path for path in sys.path if path)
        try:
            result = subprocess.run(
                [sys.executable, "-m", "nibs._lazer_verify"],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                env=env,
                timeout=VERIFY_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return False
        if result.returncode == 2:
            raise BackendUnavailable(result.stderr.strip() or "native verifier unavailable")
        return result.returncode == 0 and result.stdout.strip() == "accept"

    def _verify_native(self, statement, proof):
        _check_supported_parameters(statement)
        system = encode_statement(statement)
        _check_profile(system)
        lazer, params = _load_native()
        _, matrix, target = _native_statement(lazer, system)
        verifier = lazer.lin_verifier_state_t(self._seed(statement), params)
        verifier.set_statement(matrix, target)
        # Alternating guard bits terminate both unary code variants. The
        # subprocess remains necessary: the upstream parser is not bounded.
        buffer = lazer.ffi.new("uint8_t[]", proof + b"\x55" * MAX_PROOF_BYTES)
        consumed = lazer.ffi.new("size_t[1]")
        accepted = lazer.lib.lin_verifier_verify(verifier.ptr, buffer, consumed)
        return accepted == 1 and int(consumed[0]) == len(proof)
