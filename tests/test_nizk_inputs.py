import base64
from dataclasses import replace
from fractions import Fraction
import json
from random import Random
import subprocess
import unittest
from unittest.mock import patch

from nibs.l2 import Statement, Witness, statement_from_dict
from nibs.nizk import LazerNIZK
from nibs.protocol import (
    derive_message,
    issue_presignature,
    receiver_keygen,
    sample_signer_matrix,
    setup,
)
from nibs.regev import encrypt, keygen


class NIZKInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rng = Random(7)
        pp = setup(rng=rng)
        C = sample_signer_matrix(pp, rng)
        receiver, public = receiver_keygen(pp, rng)
        presignature = issue_presignature(pp, C, public, rng)
        pk, _ = keygen(rng=rng)
        plaintext = receiver.x + presignature.y + presignature.z
        ciphertext, randomness = encrypt(pk, plaintext, rng=rng)
        message = derive_message(pp, C, receiver, presignature)
        cls.statement = Statement(pp, C, pk, message, ciphertext)
        cls.witness = Witness(receiver, presignature, randomness)
        cls.crs_seed = bytes(range(32))
        cls.proof = b"test proof".ljust(32, b"\x00")

    def setUp(self):
        self.backend = LazerNIZK(self.crs_seed)

    def test_unserializable_public_input_is_rejected_before_worker(self):
        pp = replace(self.statement.pp, params=replace(
            self.statement.pp.params, s=Fraction(8, 1)
        ))
        statement = replace(self.statement, pp=pp)
        with patch("nibs.nizk.subprocess.run") as worker:
            self.assertFalse(self.backend.verify(statement, self.proof))
            worker.assert_not_called()

    def test_unsupported_parameters_are_rejected_before_encoding(self):
        pp = replace(self.statement.pp, params=replace(self.statement.pp.params, q=19))
        key = replace(self.statement.encryption_key, params=replace(
            self.statement.encryption_key.params, scale=513
        ))
        statements = {
            "core modulus": replace(self.statement, pp=pp),
            "encryption scale": replace(self.statement, encryption_key=key),
        }
        for profile, statement in statements.items():
            for operation in ("prove", "verify", "_verify_native"):
                with self.subTest(profile=profile, operation=operation):
                    with patch("nibs.nizk.encode_statement", side_effect=AssertionError(
                        "unsupported parameters reached the matrix encoder"
                    )) as encoder:
                        if operation == "prove":
                            with self.assertRaises(ValueError):
                                self.backend.prove(statement, self.witness)
                        elif operation == "verify":
                            self.assertFalse(self.backend.verify(statement, self.proof))
                        else:
                            with self.assertRaises(ValueError):
                                self.backend._verify_native(statement, self.proof)
                        encoder.assert_not_called()

    def test_valid_public_input_reaches_worker(self):
        result = subprocess.CompletedProcess([], 0, stdout="accept\n", stderr="")
        with patch.dict("os.environ", {"NIBS_TEST_ENV": "preserved"}):
            with patch("nibs.nizk.subprocess.run", return_value=result) as worker:
                self.assertTrue(self.backend.verify(self.statement, self.proof))
        worker.assert_called_once()
        arguments = worker.call_args.kwargs
        payload = json.loads(arguments["input"])
        self.assertEqual(bytes.fromhex(payload["crs_seed"]), self.crs_seed)
        self.assertEqual(base64.b64decode(payload["proof"], validate=True), self.proof)
        self.assertEqual(statement_from_dict(payload["statement"]), self.statement)
        self.assertEqual(arguments["env"]["NIBS_TEST_ENV"], "preserved")
        self.assertIn("PYTHONPATH", arguments["env"])


if __name__ == "__main__":
    unittest.main()
