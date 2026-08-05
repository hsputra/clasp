"""
JWKS cache-hit verify throughput: Clasp's JwksClient.verify_cached() vs.
two real PyJWT+Redis patterns (a literal Redis GET on every verify, and
an in-process-cached key -- the fair apples-to-apples comparison, since
Clasp's cache hit is also zero-I/O).

Requires a real, local Redis instance (not mocked/faked -- the point is
to measure genuine socket I/O cost, same as a real deployment).

Usage:
    redis-server --port 6390 --daemonize yes
    pip install clasp-jwt "PyJWT[crypto]" redis
    python benchmarks/jwks_vs_pyjwt_redis.py
"""
import json
import os
import time

import jwt
import redis

KID = "bench-key"
EC_PRIVATE_PEM = b"""-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgh3P9zwNro7SElB6q
jr7LWhT8YDvQpzBVJDDMreMBKoGhRANCAAQOxGAkIYc1+dPwtMKUb5F3ABGK3nF2
0OrQZaf6iLOcXdj+JW85jyrKeneE0CUIfY5VTsd1Z068ZBjrylWo08/K
-----END PRIVATE KEY-----"""

JWKS = {
    "keys": [
        {
            "kty": "EC",
            "crv": "P-256",
            "kid": KID,
            "alg": "ES256",
            "use": "sig",
            "x": "DsRgJCGHNfnT8LTClG-RdwARit5xdtDq0GWn-oiznF0",
            "y": "2P4lbzmPKsp6d4TQJQh9jlVOx3VnTrxkGOvKVajTz8o",
        }
    ]
}

N = 5_000
REDIS_PORT = int(os.environ.get("BENCH_REDIS_PORT", 6390))
REDIS_KEY = "jwks:bench"

r = redis.Redis(host="127.0.0.1", port=REDIS_PORT, db=0)
r.set(REDIS_KEY, json.dumps(JWKS))

token = jwt.encode(
    {"sub": "bench", "exp": 4_102_444_800},
    EC_PRIVATE_PEM,
    algorithm="ES256",
    headers={"kid": KID},
)

# Sanity check before timing.
jwk_from_redis = json.loads(r.get(REDIS_KEY))
matching = next(k for k in jwk_from_redis["keys"] if k["kid"] == KID)
signing_key = jwt.PyJWK.from_dict(matching).key
assert jwt.decode(token, signing_key, algorithms=["ES256"])["sub"] == "bench"

# --- Variant A: real Redis GET on every single verify call ---
t0 = time.perf_counter()
for _ in range(N):
    raw = r.get(REDIS_KEY)
    jwks = json.loads(raw)
    k = next(x for x in jwks["keys"] if x["kid"] == KID)
    key = jwt.PyJWK.from_dict(k).key
    jwt.decode(token, key, algorithms=["ES256"])
elapsed_a = time.perf_counter() - t0

# --- Variant B: JWKS/key fetched+built once, reused (in-process cache) ---
cached_key = jwt.PyJWK.from_dict(matching).key
t0 = time.perf_counter()
for _ in range(N):
    jwt.decode(token, cached_key, algorithms=["ES256"])
elapsed_b = time.perf_counter() - t0

per_call_a = elapsed_a / N * 1_000_000
per_call_b = elapsed_b / N * 1_000_000

print(f"N = {N}")
print(f"A) PyJWT, real Redis GET every call: {per_call_a:.2f}us/call")
print(f"B) PyJWT, in-process cached key:      {per_call_b:.2f}us/call")
print()
print("Compare against Clasp's pure-Rust cache-hit number from:")
print("  cargo run --release --example jwks_bench")
