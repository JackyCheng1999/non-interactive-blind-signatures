"""Process boundary for the upstream native proof decoder."""

import base64
import json
import sys

from .l2 import statement_from_dict
from .nizk import BackendUnavailable, LazerNIZK, MAX_PROOF_BYTES


def main():
    try:
        payload = json.load(sys.stdin)
        statement = statement_from_dict(payload["statement"])
        proof = base64.b64decode(payload["proof"], validate=True)
        if not 32 <= len(proof) <= MAX_PROOF_BYTES:
            return 1
        verifier = LazerNIZK(bytes.fromhex(payload["crs_seed"]))
        accepted = verifier._verify_native(statement, proof)
    except BackendUnavailable as error:
        print(str(error), file=sys.stderr)
        return 2
    except (ValueError, TypeError, KeyError, AttributeError):
        return 1
    if accepted:
        print("accept")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
