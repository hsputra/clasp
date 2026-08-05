# Benchmarks

The performance numbers in the main README are reproducible from these
scripts. Each one prints a real, freshly-measured number — none of this
is hardcoded or copied from a prior run.

Two of the three need separate, specifically-configured virtual
environments, because the whole point of the comparison is a real
misconfiguration/backend-selection difference — running them in the
wrong environment would silently measure the wrong thing.

## `hs256_vs_pyjwt.py`

Properly-configured PyJWT (the `cryptography` backend) vs. Clasp, HS256.

```
pip install clasp-jwt "PyJWT[crypto]"
python benchmarks/hs256_vs_pyjwt.py
```

## `rsa_ec_vs_python_jose.py`

python-jose's *default* backend (pure-Python `rsa`/`ecdsa`, not
`cryptography`) vs. Clasp, RS256 and ES256. Must run in a venv **without**
`cryptography` installed — the script checks this itself and refuses to
run (rather than silently benchmarking the wrong backend) if it's
present.

```
python -m venv /tmp/jose-venv
/tmp/jose-venv/bin/pip install clasp-jwt python-jose
/tmp/jose-venv/bin/python benchmarks/rsa_ec_vs_python_jose.py
```

## `jwks_vs_pyjwt_redis.py`

JWKS cache-hit latency: two real PyJWT+Redis patterns (Redis hit on
every call, and an in-process-cached key) vs. Clasp's `verify_cached()`.
Needs a real local Redis — not mocked, since the point is genuine socket
I/O cost.

```
redis-server --port 6390 --daemonize yes
pip install clasp-jwt "PyJWT[crypto]" redis
python benchmarks/jwks_vs_pyjwt_redis.py
```

For the Clasp-side half of this comparison (pure Rust, no Python/FFI at
all), see [`examples/jwks_bench.rs`](../examples/jwks_bench.rs):

```
cargo run --release --example jwks_bench
```
