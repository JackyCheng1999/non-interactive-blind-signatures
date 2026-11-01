from dataclasses import replace
import random
import unittest

from nibs.protocol import (
    Parameters,
    Presignature,
    PublicParameters,
    ReceiverSecret,
    check_presignature,
    derive_message,
    hash_to_syndrome,
    issue_presignature,
    receiver_keygen,
    sample_signer_matrix,
    setup,
)


class HashTests(unittest.TestCase):
    def test_known_shake_vectors(self):
        self.assertEqual(hash_to_syndrome(b"\x00", 1, 17), (1,))
        self.assertEqual(hash_to_syndrome(b"fixture", 2, 17), (15, 9))
        self.assertEqual(hash_to_syndrome(b"fixture", 3, 257), (196, 60, 32))

    def test_rejects_out_of_range_byte(self):
        # The SHAKE stream starts ff 0c. Only 0..254 fit 15 full copies of Z_17.
        self.assertEqual(hash_to_syndrome(bytes.fromhex("05ec"), 1, 17), (12,))

    def test_invalid_inputs(self):
        for delta, n, q in (("salt", 1, 17), (b"salt", 0, 17), (b"salt", 1, 1)):
            with self.subTest(delta=delta, n=n, q=q), self.assertRaises(ValueError):
                hash_to_syndrome(delta, n, q)


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.params = Parameters(n=1, m=2, q=17, s=8, delta_bytes=1)
        self.pp = PublicParameters(self.params, ((1, 2, 3, 4),), ((0, 1, 2, 3),))
        self.C = ((1, 3, 2, 4),)
        self.receiver = ReceiverSecret((1, 2, -1, 1), b"\x00")
        self.presignature = Presignature((2, -1, 3, 1), (1, -1, 1, -1))

    def assert_rejected(self, C, receiver, presignature):
        self.assertFalse(check_presignature(self.pp, C, receiver, presignature))
        with self.assertRaises(ValueError):
            derive_message(self.pp, C, receiver, presignature)

    def test_hand_computed_relation_and_message(self):
        # Ax + H(delta) = 6 + 1 = 7; Cz + By = 9 - 2 = 7 (mod 17).
        self.assertTrue(check_presignature(self.pp, self.C, self.receiver, self.presignature))
        message = derive_message(self.pp, self.C, self.receiver, self.presignature)
        # A_L*(-1, 1) + A_R*(3, 1) = 1 + 13 = 14. Top halves give 7.
        self.assertEqual(message.w, (14,))
        self.assertEqual(message.delta, b"\x00")

    def test_seeded_issuance(self):
        rng = random.Random(42)
        pp = setup(rng=rng)
        p = pp.params
        receiver, public = receiver_keygen(pp, rng=rng)
        C = sample_signer_matrix(pp, rng=rng)
        presignature = issue_presignature(pp, C, public, rng=rng)
        self.assertTrue(check_presignature(pp, C, receiver, presignature))

        expected_public = tuple(
            (sum(a * x for a, x in zip(row, receiver.x)) + h) % p.q
            for row, h in zip(pp.A, hash_to_syndrome(receiver.delta, p.n, p.q))
        )
        self.assertEqual(public, expected_public)
        for row_c, row_b, t in zip(C, pp.B, public):
            lhs = sum(c * z for c, z in zip(row_c, presignature.z))
            lhs += sum(b * y for b, y in zip(row_b, presignature.y))
            self.assertEqual(lhs % p.q, t)

        message = derive_message(pp, C, receiver, presignature)
        expected_w = tuple(
            (
                sum(row[j] * receiver.x[p.m + j] for j in range(p.m))
                + sum(row[p.m + j] * presignature.z[p.m + j] for j in range(p.m))
            ) % p.q
            for row in pp.A
        )
        self.assertEqual(message.w, expected_w)
        self.assertEqual(message.delta, receiver.delta)

    def test_wrong_receiver_and_tampered_presignature(self):
        self.assert_rejected(self.C, replace(self.receiver, x=(2, 2, -1, 1)), self.presignature)
        self.assert_rejected(self.C, self.receiver, replace(self.presignature, z=(3, -1, 3, 1)))
        self.assert_rejected(((2, 3, 2, 4),), self.receiver, self.presignature)

    def test_norm_bounds_use_integer_coordinates(self):
        # Adding q preserves the modular equations but exceeds the shortness bounds.
        self.assert_rejected(self.C, replace(self.receiver, x=(1, -15, -1, 1)), self.presignature)
        self.assert_rejected(self.C, self.receiver, replace(self.presignature, z=(19, -1, 3, 1)))

    def test_norm_boundaries_are_inclusive(self):
        receiver = replace(self.receiver, x=(8, 0, 0, 0))
        self.assertTrue(check_presignature(self.pp, ((2, 3, 2, 4),), receiver, self.presignature))
        presignature = replace(self.presignature, z=(16, 0, 0, 0))
        self.assertTrue(check_presignature(self.pp, ((8, 3, 2, 4),), self.receiver, presignature))

    def test_nonce_must_contain_only_signs(self):
        # B's first column is zero, so changing y[0] leaves the equation intact.
        for first in (0, 2, True):
            with self.subTest(first=first):
                self.assert_rejected(
                    self.C, self.receiver, replace(self.presignature, y=(first, -1, 1, -1))
                )

    def test_malformed_witnesses(self):
        for receiver in (
            replace(self.receiver, x=(1, 2, -1)),
            replace(self.receiver, x=(1.0, 2, -1, 1)),
            replace(self.receiver, delta=b""),
            replace(self.receiver, delta=b"\x00\x00"),
            replace(self.receiver, delta="\x00"),
        ):
            with self.subTest(receiver=receiver):
                self.assert_rejected(self.C, receiver, self.presignature)
        for presignature in (
            replace(self.presignature, z=(2, -1, 3)),
            replace(self.presignature, z=(2.0, -1, 3, 1)),
            replace(self.presignature, y=(1, -1, 1)),
        ):
            with self.subTest(presignature=presignature):
                self.assert_rejected(self.C, self.receiver, presignature)

    def test_matrix_dimensions_and_entries(self):
        for C in ((), ((1, 3, 2),), ((1, 3, 2, 4), (1, 3, 2, 4)), ((1.0, 3, 2, 4),)):
            with self.subTest(C=C):
                self.assert_rejected(C, self.receiver, self.presignature)
        for matrix in ((), ((1, 2, 3),), ((1, 2, 3, 4), (1, 2, 3)), ((1, 2, 3, 4.0),)):
            with self.subTest(matrix=matrix), self.assertRaises(ValueError):
                PublicParameters(self.params, matrix, self.pp.B)
            with self.subTest(matrix=matrix), self.assertRaises(ValueError):
                PublicParameters(self.params, self.pp.A, matrix)

    def test_issuance_input_validation(self):
        for public in ((), (1, 2), (1.0,)):
            with self.subTest(public=public), self.assertRaises(ValueError):
                issue_presignature(self.pp, self.C, public, rng=random.Random(1))
        with self.assertRaises(ValueError):
            issue_presignature(self.pp, self.C, (7,), rng=random.Random(1), max_attempts=0)
        with self.assertRaises(ValueError):
            issue_presignature(self.pp, ((0, 0, 2, 4),), (7,), rng=random.Random(1))

    def test_invalid_parameters(self):
        cases = (
            {"n": 0}, {"n": True}, {"n": 3, "m": 2}, {"m": 0},
            {"q": 1}, {"q": 15}, {"s": 0}, {"s": -1},
            {"s": float("inf")}, {"s": float("nan")}, {"delta_bytes": 0},
        )
        for values in cases:
            with self.subTest(values=values), self.assertRaises(ValueError):
                Parameters(**values)


if __name__ == "__main__":
    unittest.main()
