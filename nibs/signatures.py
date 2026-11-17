"""Obtain and public verification using encrypted witnesses and LNP proofs."""

from dataclasses import dataclass

from .l2 import Statement, Witness
from .protocol import derive_message
from .regev import Ciphertext, encrypt


@dataclass(frozen=True)
class Signature:
    proof: bytes
    ciphertext: Ciphertext


def obtain(pp, C, receiver, presignature, encryption_key, proof_system, rng=None):
    message = derive_message(pp, C, receiver, presignature)
    plaintext = receiver.x + presignature.y + presignature.z
    ciphertext, randomness = encrypt(encryption_key, plaintext, rng=rng)
    statement = Statement(pp, C, encryption_key, message, ciphertext)
    witness = Witness(receiver, presignature, randomness)
    proof = proof_system.prove(statement, witness)
    return message, Signature(proof, ciphertext)


def verify(pp, C, encryption_key, message, signature, proof_system):
    if not isinstance(signature, Signature):
        return False
    statement = Statement(pp, C, encryption_key, message, signature.ciphertext)
    return proof_system.verify(statement, signature.proof)
