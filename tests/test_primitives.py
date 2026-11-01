import random
import unittest

from nibs.linalg import add_mod, has_full_row_rank, matvec, random_matrix, squared_norm, sub_mod
from nibs.sampling import DiscreteGaussian, sample_bonsai_preimage, sample_vector


class LinearAlgebraTests(unittest.TestCase):
    def test_modular_arithmetic(self):
        self.assertEqual(matvec(((1, 2), (-3, 4)), (5, -1), 7), (3, 2))
        self.assertEqual(add_mod((5, -1), (4, 3), 7), (2, 2))
        self.assertEqual(sub_mod((1, 0), (3, 2), 7), (5, 5))
        self.assertEqual(squared_norm((-3, 0, 4)), 25)

    def test_invalid_dimensions(self):
        for matrix, vector in (((), ()), (((),), ()), (((1, 2), (3,)), (1, 2)), (((1, 2),), (1,))):
            with self.subTest(matrix=matrix), self.assertRaises(ValueError):
                matvec(matrix, vector, 7)
        for operation in (add_mod, sub_mod):
            with self.assertRaises(ValueError):
                operation((1,), (1, 2), 7)

    def test_rank_over_a_prime_field(self):
        self.assertTrue(has_full_row_rank(((0, 1), (1, 1)), 5))
        self.assertTrue(has_full_row_rank(((1, 2, 3), (2, 4, 2)), 5))
        self.assertFalse(has_full_row_rank(((1, 2), (3, 6)), 5))
        self.assertFalse(has_full_row_rank(((1,), (2,)), 5))
        self.assertFalse(has_full_row_rank(((5, 0),), 5))
        with self.assertRaises(ValueError):
            has_full_row_rank(((1,),), 1)

    def test_random_matrix_shape_and_entries(self):
        matrix = random_matrix(2, 3, 7, random.Random(9))
        self.assertIsInstance(matrix, tuple)
        self.assertEqual(tuple(len(row) for row in matrix), (3, 3))
        self.assertTrue(all(0 <= x < 7 for row in matrix for x in row))
        for rows, cols in ((0, 1), (1, 0), (-1, 2), (1.5, 2)):
            with self.assertRaises(ValueError):
                random_matrix(rows, cols, 7, random.Random(0))


class SamplingTests(unittest.TestCase):
    def test_gaussian_parameter_and_support(self):
        for s in (0, -1, float("nan"), float("inf"), None):
            with self.subTest(s=s), self.assertRaises(ValueError):
                DiscreteGaussian(s)
        gaussian = DiscreteGaussian(1.25)
        rng = random.Random(10)
        self.assertTrue(all(abs(gaussian.sample(rng)) <= 10 for _ in range(100)))
        self.assertEqual(DiscreteGaussian(1e-200).sample(rng), 0)
        self.assertEqual(sample_vector(0, 1, rng), ())
        with self.assertRaises(ValueError):
            sample_vector(-1, 1, rng)

    def test_preimage_equation_and_fixed_bottom(self):
        C = ((1, 2, 1, 0), (0, 1, 1, 1))
        target = (-1, 4)
        rng = random.Random(73)
        expected_bottom = sample_vector(2, 1.5, random.Random(73))
        preimage = sample_bonsai_preimage(C, target, 3, 1.5, rng)
        self.assertEqual(len(preimage), 4)
        self.assertEqual(preimage[2:], expected_bottom)
        self.assertEqual(matvec(C, preimage, 3), (2, 1))

    def test_preimage_exhaustion_does_not_resample_bottom(self):
        class ZeroDraws:
            calls = 0

            def random(self):
                self.calls += 1
                return 0.5

        rng = ZeroDraws()
        with self.assertRaisesRegex(RuntimeError, "3 attempts"):
            sample_bonsai_preimage(((1, 0),), (1,), 3, 1, rng, max_attempts=3)
        self.assertEqual(rng.calls, 4)

    def test_preimage_input_validation(self):
        cases = (
            (((1, 0, 0),), (0,), 3, 1, 10),
            (((1, 0),), (0, 0), 3, 1, 10),
            (((0, 1),), (0,), 3, 1, 10),
            (((1, 0),), (0,), 1, 1, 10),
            (((1, 0),), (0,), 3, 0, 10),
            (((1, 0),), (0,), 3, 1, 0),
        )
        for C, target, q, s, attempts in cases:
            with self.subTest(C=C, target=target, q=q, s=s), self.assertRaises(ValueError):
                sample_bonsai_preimage(C, target, q, s, random.Random(0), attempts)


if __name__ == "__main__":
    unittest.main()
