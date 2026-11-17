from math import sqrt

# Scalar coordinates are constant polynomials in Z_mod[X]/(X^64 + 1).
vname = "nibs_l2"
deg = 64
mod = 17 * 65537
dim = (244, 432)

# x, z, then binary nonce bits and encryption randomness.
wpart = [list(range(16)), list(range(16, 32)), list(range(32, 432))]
wl2 = [sqrt(16), sqrt(1024), 0]
wbin = [0, 0, 1]
wlinf = 32
