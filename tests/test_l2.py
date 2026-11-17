from dataclasses import replace
import json
import random
import unittest

from nibs.l2 import (
    Statement,
    Witness,
    check_witness,
    encode_statement,
    encode_witness,
    statement_bytes,
    statement_from_dict,
)
from nibs.protocol import (
    Message,
    Parameters,
    Presignature,
    PublicParameters,
    ReceiverSecret,
    derive_message,
    issue_presignature,
    receiver_keygen,
    sample_signer_matrix,
    setup,
)
from nibs.regev import (
    Ciphertext,
    EncryptionRandomness,
    Params,
    PublicKey,
    decrypt,
    encrypt,
    keygen,
)


class L2Tests(unittest.TestCase):
    def setUp(self):
        core = Parameters(n=1, m=2, q=17, s=8, delta_bytes=1)
        pp = PublicParameters(core, ((1, 2, 3, 4),), ((0, 1, 2, 3),))
        encryption = Params(dimension=2, samples=3)
        pk = PublicKey(encryption, ((1, 2), (3, 4), (5, 6)), (30, 64, 101))
        ciphertext = Ciphertext(
            ((6, 8), (8, 10), (4, 6), (9, 12)) * 3,
            (643, 1189, 65119, 707, 643, 65190, 606, 65220, 1155, 65190, 1630, 707),
        )
        self.statement = Statement(pp, ((9, 3, 2, 5),), pk, Message((14,), b"\x00"), ciphertext)
        self.witness = Witness(
            ReceiverSecret((1, 2, -1, 1), b"\x00"),
            Presignature((2, -1, 3, 1), (1, -1, 1, -1)),
            EncryptionRandomness(((1, 0, 1), (0, 1, 1), (1, 1, 0), (1, 1, 1)) * 3),
        )

    def assert_invalid_relation(self, statement, witness=None):
        witness = self.witness if witness is None else witness
        self.assertFalse(check_witness(encode_statement(statement), encode_witness(statement, witness)))

    def assert_equations_hold(self, system, vector):
        for row, target in zip(system.matrix, system.rhs):
            self.assertEqual(sum(a * b for a, b in zip(row, vector)) % system.modulus, target)

    def test_hand_computed_witness(self):
        system = encode_statement(self.statement)
        vector = encode_witness(self.statement, self.witness)
        self.assertEqual(vector[:12], (1, 2, -1, 1, 2, -1, 3, 1, 1, 0, 1, 0))
        self.assertEqual(vector[12:], (1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1) * 3)
        self.assertEqual((len(system.matrix), system.columns, system.width), (38, 48, 4))
        self.assertEqual((system.receiver_bound_squared, system.presignature_bound_squared), (64, 256))
        self.assert_equations_hold(system, vector)
        self.assertTrue(check_witness(system, vector))

    def test_scalar_equations_and_cross_modulus_embedding(self):
        system = encode_statement(self.statement)
        self.assertEqual(system.modulus, 1114129)  # 17 * 65537

        def row(index, coefficients, rhs):
            expected = tuple(coefficients.get(i, 0) for i in range(48))
            self.assertEqual(system.matrix[index], expected)
            self.assertEqual(system.rhs[index], rhs)

        # Cz + By - Ax - H(delta) = 26 - 2 - 6 - 1 = 17, not zero over Z.
        row(0, {
            0: 1048592, 1: 983055, 2: 917518, 3: 851981,
            4: 589833, 5: 196611, 6: 131074, 7: 327685,
            9: 131074, 10: 262148, 11: 393222,
        }, 458759)
        # w = 1*(-1) + 2*1 + 3*3 + 4*1 = 14, using both bottom halves.
        row(1, {2: 65537, 3: 131074, 6: 196611, 7: 262148}, 917518)
        # First encrypted coordinate: r=(1,0,1), u=(6,8), v=131+512=643.
        row(2, {12: 17, 13: 51, 14: 85}, 102)
        row(3, {12: 34, 13: 68, 14: 102}, 136)
        row(4, {0: 8704, 12: 510, 13: 1088, 14: 1717}, 10931)
        # A negative plaintext gives 94-512=-418 = 65119 mod 65537.
        row(10, {2: 8704, 18: 510, 19: 1088, 20: 1717}, 1107023)
        # Signed y is encoded as 2*bit-1, so v gains one scale on the RHS.
        row(16, {8: 17408, 24: 510, 25: 1088, 26: 1717}, 19635)
        row(19, {9: 17408, 27: 510, 28: 1088, 29: 1717}, 2805)
        # Ciphertext coordinate 8 encrypts z[0], at witness column 4.
        row(28, {4: 8704, 36: 510, 37: 1088, 38: 1717}, 19635)

        ciphertext = replace(self.statement.ciphertext, v=(660,) + self.statement.ciphertext.v[1:])
        self.assert_invalid_relation(replace(self.statement, ciphertext=ciphertext))

    def test_default_profile(self):
        rng = random.Random(42)
        pp = setup(rng=rng)
        receiver, public = receiver_keygen(pp, rng=rng)
        C = sample_signer_matrix(pp, rng=rng)
        presignature = issue_presignature(pp, C, public, rng=rng)
        message = derive_message(pp, C, receiver, presignature)
        pk, sk = keygen(rng=random.Random(43))
        plaintext = receiver.x + presignature.y + presignature.z
        ciphertext, randomness = encrypt(pk, plaintext, rng=random.Random(44))
        statement = Statement(pp, C, pk, message, ciphertext)
        witness = Witness(receiver, presignature, randomness)
        system = encode_statement(statement)
        self.assertEqual((len(system.matrix), system.columns), (244, 432))
        self.assertEqual((system.receiver_bound_squared, system.presignature_bound_squared), (16, 1024))
        self.assertEqual(decrypt(sk, ciphertext), plaintext)
        self.assertTrue(check_witness(system, encode_witness(statement, witness)))

    def test_changed_message_and_salt(self):
        self.assert_invalid_relation(replace(self.statement, message=Message((15,), b"\x00")))
        changed = replace(self.statement, message=Message((14,), b"\x01"))
        with self.assertRaises(ValueError):
            encode_witness(changed, self.witness)
        witness = replace(self.witness, receiver=replace(self.witness.receiver, delta=b"\x01"))
        self.assert_invalid_relation(changed, witness)

    def test_changed_core_matrices_and_encryption_key(self):
        pp = self.statement.pp
        for changed in (
            replace(self.statement, pp=replace(pp, A=((2, 2, 3, 4),))),
            replace(self.statement, pp=replace(pp, B=((1, 1, 2, 3),))),
            replace(self.statement, C=((10, 3, 2, 5),)),
            replace(self.statement, encryption_key=replace(self.statement.encryption_key, b=(31, 64, 101))),
            replace(self.statement, encryption_key=replace(
                self.statement.encryption_key, A=((2, 2), (3, 4), (5, 6))
            )),
        ):
            with self.subTest(statement=changed):
                self.assert_invalid_relation(changed)

    def test_ciphertext_and_randomness_are_bound_to_the_witness(self):
        ct = self.statement.ciphertext
        self.assert_invalid_relation(replace(self.statement, ciphertext=replace(
            ct, u=((7, 8),) + ct.u[1:]
        )))
        self.assert_invalid_relation(replace(self.statement, ciphertext=replace(
            ct, v=(644,) + ct.v[1:]
        )))
        randomness = replace(self.witness.randomness, rows=((0, 0, 1),) + self.witness.randomness.rows[1:])
        self.assert_invalid_relation(self.statement, replace(self.witness, randomness=randomness))

        plaintext = (2, 2, -1, 1) + self.witness.presignature.y + self.witness.presignature.z
        other_ct, _ = encrypt(self.statement.encryption_key, plaintext, self.witness.randomness)
        self.assert_invalid_relation(replace(self.statement, ciphertext=other_ct))

    def test_nonce_is_binary_and_shares_the_ciphertext_coordinates(self):
        # B's first column is zero; changing y[0] only breaks the encryption relation.
        changed = replace(self.witness.presignature, y=(-1, -1, 1, -1))
        self.assert_invalid_relation(self.statement, replace(self.witness, presignature=changed))
        for y in ((0, -1, 1, -1), (2, -1, 1, -1), (True, -1, 1, -1)):
            with self.subTest(y=y), self.assertRaises(ValueError):
                encode_witness(self.statement, replace(
                    self.witness, presignature=replace(self.witness.presignature, y=y)
                ))
        system = encode_statement(self.statement)
        vector = list(encode_witness(self.statement, self.witness))
        for column in (8, 12):
            changed = vector.copy()
            changed[column] = 2
            self.assertFalse(check_witness(system, tuple(changed)))

    def test_norm_bounds_are_checked_beyond_the_linear_equations(self):
        for receiver, presignature in (
            (replace(self.witness.receiver, x=(1, -15, -1, 1)), self.witness.presignature),
            (self.witness.receiver, replace(self.witness.presignature, z=(19, -1, 3, 1))),
        ):
            plaintext = receiver.x + presignature.y + presignature.z
            ciphertext, _ = encrypt(self.statement.encryption_key, plaintext, self.witness.randomness)
            statement = replace(self.statement, ciphertext=ciphertext)
            witness = replace(self.witness, receiver=receiver, presignature=presignature)
            system = encode_statement(statement)
            vector = encode_witness(statement, witness)
            self.assert_equations_hold(system, vector)
            self.assertFalse(check_witness(system, vector))

    def test_rejects_malformed_statements(self):
        for statement in (
            replace(self.statement, C=((9, 3, 2),)),
            replace(self.statement, C=((17, 3, 2, 5),)),
            replace(self.statement, message=Message((17,), b"\x00")),
            replace(self.statement, message=Message((14,), b"\x00\x00")),
            replace(self.statement, ciphertext=Ciphertext(
                self.statement.ciphertext.u[:-1], self.statement.ciphertext.v[:-1]
            )),
            replace(self.statement, ciphertext=replace(
                self.statement.ciphertext, u=((1,),) + self.statement.ciphertext.u[1:]
            )),
        ):
            with self.subTest(statement=statement), self.assertRaises(ValueError):
                encode_statement(statement)
        pk = replace(self.statement.encryption_key, params=replace(
            self.statement.encryption_key.params, plaintext_bound=15
        ))
        with self.assertRaisesRegex(ValueError, "plaintext range"):
            encode_statement(replace(self.statement, encryption_key=pk))

    def test_rejects_malformed_witnesses(self):
        for witness in (
            replace(self.witness, receiver=replace(self.witness.receiver, x=(1, 2, -1))),
            replace(self.witness, receiver=replace(self.witness.receiver, x=(1.0, 2, -1, 1))),
            replace(self.witness, randomness=EncryptionRandomness(((1, 0, 1),))),
            replace(self.witness, randomness=EncryptionRandomness(((1, 0),) * 12)),
        ):
            with self.subTest(witness=witness), self.assertRaises(ValueError):
                encode_witness(self.statement, witness)
        system = encode_statement(self.statement)
        vector = encode_witness(self.statement, self.witness)
        self.assertFalse(check_witness(system, vector[:-1]))
        self.assertFalse(check_witness(system, (True,) + vector[1:]))

    def test_canonical_public_json_and_roundtrip(self):
        payload = statement_bytes(self.statement)
        data = json.loads(payload)
        self.assertEqual(set(data), {"pp", "C", "encryption_key", "message", "ciphertext"})
        self.assertEqual(data["message"], {"w": [14], "delta": "00"})
        self.assertEqual(data["C"], [[9, 3, 2, 5]])
        self.assertEqual(set(data["encryption_key"]), {"params", "A", "b"})
        self.assertEqual(payload, json.dumps(data, sort_keys=True, separators=(",", ":")).encode("ascii"))
        parsed = statement_from_dict(dict(reversed(list(data.items()))))
        self.assertEqual(parsed, self.statement)
        self.assertEqual(statement_bytes(parsed), payload)
        self.assertTrue(check_witness(encode_statement(parsed), encode_witness(parsed, self.witness)))
        changed = replace(self.statement, message=Message((15,), b"\x00"))
        self.assertNotEqual(statement_bytes(changed), payload)


if __name__ == "__main__":
    unittest.main()
