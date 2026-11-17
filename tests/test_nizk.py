"""Opt-in integration checks against the compiled LaZer backend."""

from dataclasses import replace
import os
from random import Random
import unittest

from nibs.l2 import Statement, encode_statement
from nibs.nizk import LazerNIZK
from nibs.protocol import (
    hash_to_syndrome,
    issue_presignature,
    receiver_keygen,
    sample_signer_matrix,
    setup,
)
from nibs.regev import decrypt, keygen
from nibs.signatures import obtain, verify


@unittest.skipUnless(
    os.environ.get("NIBS_RUN_LAZER_TESTS") == "1",
    "set NIBS_RUN_LAZER_TESTS=1 to run the compiled LaZer integration tests",
)
class LazerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rng = Random(7)
        cls.pp = setup(rng=rng)
        cls.C = sample_signer_matrix(cls.pp, rng)
        cls.receiver, public = receiver_keygen(cls.pp, rng)
        cls.presignature = issue_presignature(cls.pp, cls.C, public, rng)
        cls.pk, cls.sk = keygen(rng=rng)
        cls.crs_seed = bytes(range(32))
        prover = LazerNIZK(cls.crs_seed)
        cls.message, cls.signature = obtain(
            cls.pp, cls.C, cls.receiver, cls.presignature, cls.pk, prover, rng
        )

    def public_verify(self, **changes):
        arguments = {
            "pp": self.pp,
            "C": self.C,
            "encryption_key": self.pk,
            "message": self.message,
            "signature": self.signature,
            "proof_system": LazerNIZK(self.crs_seed),
        }
        arguments.update(changes)
        return verify(**arguments)

    def test_public_verification(self):
        self.assertGreaterEqual(len(self.signature.proof), 32)
        self.assertTrue(self.public_verify())

    def test_ciphertext_recovers_the_same_witness(self):
        expected = self.receiver.x + self.presignature.y + self.presignature.z
        self.assertEqual(decrypt(self.sk, self.signature.ciphertext), expected)

    def test_changed_public_inputs(self):
        q = self.pp.params.q
        eq = self.pk.params.q

        def changed_first(matrix, modulus):
            row = ((matrix[0][0] + 1) % modulus,) + matrix[0][1:]
            return (row,) + matrix[1:]

        ct = self.signature.ciphertext
        other_pk, _ = keygen(rng=Random(83))
        cases = {
            "message": {"message": replace(
                self.message, w=((self.message.w[0] + 1) % q,) + self.message.w[1:]
            )},
            "A": {"pp": replace(self.pp, A=changed_first(self.pp.A, q))},
            "B": {"pp": replace(self.pp, B=changed_first(self.pp.B, q))},
            "C": {"C": changed_first(self.C, q)},
            "encryption key": {"encryption_key": other_pk},
            "encryption A": {"encryption_key": replace(self.pk, A=changed_first(self.pk.A, eq))},
            "encryption b": {"encryption_key": replace(
                self.pk, b=((self.pk.b[0] + 1) % eq,) + self.pk.b[1:]
            )},
            "ciphertext u": {"signature": replace(
                self.signature, ciphertext=replace(ct, u=changed_first(ct.u, eq))
            )},
            "ciphertext v": {"signature": replace(self.signature, ciphertext=replace(
                ct, v=((ct.v[0] + 1) % eq,) + ct.v[1:]
            ))},
            "CRS seed": {"proof_system": LazerNIZK(bytes(range(31)) + b"\x20")},
        }
        for name, changes in cases.items():
            with self.subTest(input=name):
                self.assertFalse(self.public_verify(**changes))

    def test_raw_salt_is_bound_even_when_its_syndrome_collides(self):
        p = self.pp.params
        original = self.message.delta
        target = hash_to_syndrome(original, p.n, p.q)
        collision = None
        for i in range(100_000):
            candidate = i.to_bytes(p.delta_bytes, "big")
            if candidate != original and hash_to_syndrome(candidate, p.n, p.q) == target:
                collision = candidate
                break
        self.assertIsNotNone(collision, "no salt collision found at the toy parameters")
        message = replace(self.message, delta=collision)
        original_statement = Statement(self.pp, self.C, self.pk, self.message, self.signature.ciphertext)
        changed_statement = replace(original_statement, message=message)
        self.assertEqual(encode_statement(original_statement), encode_statement(changed_statement))
        self.assertFalse(self.public_verify(message=message))

    def test_invalid_proof_encodings(self):
        proof = self.signature.proof
        middle = len(proof) // 2
        flipped = proof[:middle] + bytes((proof[middle] ^ 1,)) + proof[middle + 1:]
        cases = {
            "bit flipped": flipped,
            "truncated": proof[:-1],
            "appended": proof + b"\x00",
            "empty": b"",
            "random": Random(91).randbytes(96),
        }
        for name, invalid in cases.items():
            with self.subTest(encoding=name):
                self.assertFalse(self.public_verify(signature=replace(self.signature, proof=invalid)))


if __name__ == "__main__":
    unittest.main()
