from dataclasses import fields, replace
import random
import unittest

from nibs.regev import (
    Ciphertext,
    EncryptionRandomness,
    Params,
    PublicKey,
    SecretKey,
    decrypt,
    encrypt,
    keygen,
)


class RegevTests(unittest.TestCase):
    def setUp(self):
        self.params = Params(dimension=2, samples=3, q=257, scale=16, plaintext_bound=7)
        self.pk = PublicKey(self.params, ((1, 2), (3, 4), (5, 6)), (30, 64, 101))
        self.sk = SecretKey(self.params, (7, 11))
        self.randomness = EncryptionRandomness(((1, 0, 1), (0, 1, 1), (1, 1, 0)))

    def test_hand_computed_encryption(self):
        # A*s = (29, 65, 101); the public-key errors are (1, -1, 0).
        ciphertext, randomness = encrypt(self.pk, (-7, 0, 7), self.randomness)
        self.assertEqual(ciphertext.u, ((6, 8), (8, 10), (4, 6)))
        self.assertEqual(ciphertext.v, (19, 165, 206))
        self.assertEqual(randomness, self.randomness)
        self.assertEqual(decrypt(self.sk, ciphertext), (-7, 0, 7))

    def test_seeded_key_generation_and_roundtrip(self):
        pk, sk = keygen(rng=random.Random(12))
        self.assertEqual({f.name for f in fields(sk)}, {"params", "s"})
        for row, b in zip(pk.A, pk.b):
            error = (b - sum(a * s for a, s in zip(row, sk.s))) % pk.params.q
            if error > pk.params.q // 2:
                error -= pk.params.q
            self.assertLessEqual(abs(error), pk.params.error_bound)
        message = (-63, -2, -1, 0, 1, 2, 63)
        ciphertext, randomness = encrypt(pk, message, rng=random.Random(13))
        self.assertEqual(decrypt(sk, ciphertext), message)
        self.assertEqual(len(randomness.rows), len(message))
        self.assertTrue(all(len(row) == pk.params.samples for row in randomness.rows))
        self.assertTrue(all(x in (0, 1) for row in randomness.rows for x in row))
        self.assertGreater(len(set(randomness.rows)), 1)
        self.assertEqual(encrypt(pk, message, randomness)[0], ciphertext)

    def test_full_noise_bound_at_both_plaintext_extremes(self):
        zero_A = ((0, 0),) * self.params.samples
        sk = SecretKey(self.params, (0, 0))
        randomness = EncryptionRandomness(((1, 1, 1), (1, 1, 1)))
        for error in (-1, 1):
            pk = PublicKey(self.params, zero_A, (error % self.params.q,) * self.params.samples)
            with self.subTest(error=error):
                ciphertext, _ = encrypt(pk, (-7, 7), randomness)
                self.assertEqual(decrypt(sk, ciphertext), (-7, 7))

    def test_zero_subset_is_valid(self):
        randomness = EncryptionRandomness(((0, 0, 0), (0, 0, 0)))
        ciphertext, _ = encrypt(self.pk, (-7, 7), randomness)
        self.assertEqual(ciphertext.u, ((0, 0), (0, 0)))
        self.assertEqual(ciphertext.v, (145, 112))
        self.assertEqual(decrypt(self.sk, ciphertext), (-7, 7))

    def test_odd_scale_and_zero_error(self):
        params = Params(dimension=1, samples=1, q=23, scale=3, plaintext_bound=3, error_bound=0)
        pk = PublicKey(params, ((2,),), (8,))
        sk = SecretKey(params, (4,))
        ciphertext, _ = encrypt(pk, (-3, 0, 3), EncryptionRandomness(((1,), (1,), (1,))))
        self.assertEqual(decrypt(sk, ciphertext), (-3, 0, 3))

    def test_rejects_invalid_messages(self):
        for message in ((), (-8,), (8,), (True,), (1.0,), "1", None):
            with self.subTest(message=message), self.assertRaises(ValueError):
                encrypt(self.pk, message)

    def test_rejects_invalid_randomness(self):
        for rows in ((), ((0, 2, 1),), ((0, -1, 1),), ((False, 1, 0),), ((0.0, 1, 0),)):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                EncryptionRandomness(rows)
        for randomness in (
            EncryptionRandomness(((1, 0),)),
            EncryptionRandomness(((1, 0, 1), (0, 1, 0))),
            ((1, 0, 1),),
        ):
            with self.subTest(randomness=randomness), self.assertRaises(ValueError):
                encrypt(self.pk, (1,), randomness)

    def test_rejects_invalid_keys(self):
        for A in ((), ((1,), (2,), (3,)), ((1, 2), (3, 4)), ((-1, 2), (3, 4), (5, 6))):
            with self.subTest(A=A), self.assertRaises(ValueError):
                PublicKey(self.params, A, self.pk.b)
        for b in ((1, 2), (1, 2, 257), (1, False, 3)):
            with self.subTest(b=b), self.assertRaises(ValueError):
                PublicKey(self.params, self.pk.A, b)
        for s in ((1,), (1, 257), (-1, 2), (1.0, 2)):
            with self.subTest(s=s), self.assertRaises(ValueError):
                SecretKey(self.params, s)

    def test_rejects_invalid_ciphertexts(self):
        for u, v in (((), ()), (((0, 0),), ()), (((False, 0),), (0,))):
            with self.subTest(u=u, v=v), self.assertRaises(ValueError):
                Ciphertext(u, v)
        for ciphertext in (
            Ciphertext(((0,),), (0,)),
            Ciphertext(((257, 0),), (0,)),
            Ciphertext(((0, -1),), (0,)),
            Ciphertext(((0, 0),), (257,)),
        ):
            with self.subTest(ciphertext=ciphertext), self.assertRaises(ValueError):
                decrypt(self.sk, ciphertext)
        # The phase is halfway between encodings, beyond any allowed error.
        with self.assertRaisesRegex(ValueError, "noise bound"):
            decrypt(self.sk, Ciphertext(((0, 0),), (8,)))
        with self.assertRaisesRegex(ValueError, "plaintext"):
            decrypt(self.sk, Ciphertext(((0, 0),), (128,)))

    def test_tampering_and_malleability(self):
        ciphertext, _ = encrypt(self.pk, (-7, 0, 7), self.randomness)
        modified = replace(ciphertext, v=(24, 165, 206))
        with self.assertRaises(ValueError):
            decrypt(self.sk, modified)
        # Adding an entire encoding step can still produce another valid plaintext.
        modified = replace(ciphertext, v=(35, 165, 206))
        self.assertEqual(decrypt(self.sk, modified), (-6, 0, 7))

    def test_invalid_parameters(self):
        cases = (
            {"dimension": 0}, {"dimension": True}, {"samples": -1}, {"q": 1},
            {"q": 65535}, {"scale": 0}, {"plaintext_bound": 0}, {"error_bound": -1},
            {"error_bound": 1.0}, {"scale": 16}, {"q": 65521, "scale": 1024},
        )
        for values in cases:
            with self.subTest(values=values), self.assertRaises(ValueError):
                Params(**values)

    def test_constructor_freezes_input_lists(self):
        A = [[1, 2], [3, 4], [5, 6]]
        b = [30, 64, 101]
        pk = PublicKey(self.params, A, b)
        rows = [[1, 0, 1]]
        randomness = EncryptionRandomness(rows)
        A[0][0] = 100
        b[0] = 100
        rows[0][0] = 0
        self.assertEqual(pk, self.pk)
        self.assertEqual(randomness.rows, ((1, 0, 1),))


if __name__ == "__main__":
    unittest.main()
