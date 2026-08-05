"""
HS256 verify throughput: Clasp vs. properly-configured PyJWT (the
`cryptography` backend, i.e. PyJWT installed as `PyJWT[crypto]` -- not a
strawman pure-Python comparison).

Usage:
    pip install clasp-jwt "PyJWT[crypto]"
    python benchmarks/hs256_vs_pyjwt.py
"""
import time

import clasp
import jwt

SECRET = b"a-secret-thats-long-enough-for-hs256-per-rfc-7518"
N = 50_000

token = jwt.encode(
    {"sub": "bench", "exp": 4_102_444_800},
    SECRET,
    algorithm="HS256",
)

# Sanity check both paths agree before timing.
assert jwt.decode(token, SECRET, algorithms=["HS256"])["sub"] == "bench"
key = clasp.SymmetricKey(SECRET, "HS256")
assert "bench" in key.verify(token)

t0 = time.perf_counter()
for _ in range(N):
    jwt.decode(token, SECRET, algorithms=["HS256"])
elapsed_pyjwt = time.perf_counter() - t0

t0 = time.perf_counter()
for _ in range(N):
    key.verify(token)
elapsed_clasp = time.perf_counter() - t0

throughput_pyjwt = N / elapsed_pyjwt
throughput_clasp = N / elapsed_clasp

print(f"N = {N}")
print(f"PyJWT (cryptography backend): {throughput_pyjwt:,.0f}/sec")
print(f"Clasp:                        {throughput_clasp:,.0f}/sec")
print(f"Speedup: {throughput_clasp / throughput_pyjwt:.2f}x")
