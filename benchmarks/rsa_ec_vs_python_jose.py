"""
RSA (RS256) and EC (ES256) verify throughput: Clasp vs. python-jose's
*default* backend.

python-jose silently falls back to pure-Python `rsa`/`ecdsa` unless the
`cryptography` extra is installed -- a real, common misconfiguration, not
a strawman. This script must be run in a venv WITHOUT `cryptography`
installed, or it will (correctly) refuse to run, since it'd otherwise
silently benchmark the wrong backend.

Usage:
    python -m venv /tmp/jose-venv && /tmp/jose-venv/bin/pip install \\
        clasp-jwt python-jose
    /tmp/jose-venv/bin/python benchmarks/rsa_ec_vs_python_jose.py
"""
import sys
import time

import clasp
from jose import jwt as jose_jwt

try:
    import cryptography  # noqa: F401

    print(
        "ERROR: `cryptography` is installed in this venv, which makes "
        "python-jose use its fast backend instead of the default "
        "pure-Python one this benchmark targets. Run this in a clean "
        "venv with only `python-jose` (no [cryptography] extra) and "
        "`clasp-jwt` installed.",
        file=sys.stderr,
    )
    sys.exit(1)
except ImportError:
    pass  # expected -- this is the misconfiguration being benchmarked

N = 2_000

RSA_PRIVATE_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCcKwu+riUEE2Lr
pk3YDWMFBL4hITGv+gzZ9hS4gni8casan3dFRNhdE6+KzBcEYM1yR4llGuvr8+zc
Kcu70GloY9Pls+AEbYsyxQjWiV3IxkLf6oOIooPsd0dbJPFwzFzKOmA5qYvCeLzp
xIEUv0SnIjVzNxbPB0RLMgFpvDsyoTXQJgqqs0A2EvrmIpXkLqEZU+stQJVy9Ufn
byfaH/FiZtuTy92OinYptwd0kDa7xxhvE5RAg8FnV6EwI13QTPQFTss3k1+W2oWS
dNf8YksGovoz3Vl/nmpE/omKPZdhcTko9+nA/7wkrXUE7QwMQPT7WZ8hwJnw9yfl
l1wUwesfAgMBAAECggEAQwE5JdQkL659t+v/5F5CCQoy5ZYPcpjP4MjztQLN+NSw
fFjFXOQgDTeADwZoLcm2/HxzF/1IElHzY7dPIcNXJqIGbb0StfOmUN83Xo1LvvRK
BzbgvsQz5EZ9SD7+lM4qVd5cIQF85LDXJVnZpGQ4eZl0431UfPl6NOU8s/g+Ugcr
M/oE5Z7z82Ktx1NZ06qy0A9IhHqaoK1bR23Ih5LqqYr6K6eNpsFNeAa+cYDjQYLP
1nt7XoNsfTJOgHoXpsOqV+C4B+gKo0UB3tNg2Vk1ebmbGT5ZlZof9v19K7XP6zb3
HncHK8l+Ffc/cP0GirsupPl0UqzsbsxubMuLOsoxWQKBgQDXsVwx4TZ+77YKeS6P
7z/riVDbGFJatgxxNi77o6a1tkoJrPHlThuEB5+rzKdHj7qIIeIuQ+FwhlKcDjqX
XqpZqwCCJV06M37/lQ+nYyZmOkvNYtnZ0tbakDxQYgwVwD9ps3Xd9LpEsQA/VrV+
aiSzCJCv5LTJJ9JeQNNzidIWNQKBgQC5Wg33IBsP5TTvGKpqKohyZ0ByawJk6jru
aSLSPf+naCToM4LSZyK28aoMlX+ORdcuyxLF+NuSbrNScBl7NVgxkWdU8kYAI+Cd
q9jVejvXOXiuFClySs/w7ax9e2DXoJqWUT6pDkw9w4ILCyg8N4fK5qFD1Ur4XTJl
d+seqfgWgwKBgHHKuTf7d/Op5WFLI1x+PTu2+vhLsY73wkKr8keBw/7Tx+Wo3wk5
ltyl5QAO/SWM1zzgm2ILH9FsnAKGozSelcKuq5r9uVxuNI8EBfkqHuUJ1lnpz8LS
L9WpCJjj0TpcbVgHfKR3axm4Q8gmp6Okve3SE/sn7pS9NIfTLXsj97kNAoGACh0X
1fwyfdOL59/4rIJVn6hyo8ui/c6qGIg0FjS71m6gVOs6oDBwfHsDRFyD8UduTmdW
RuclVAAmWME1IrvubAX7FW+C0k8i2neeBUf+K+g+5YDEIjBi2Eqfttkcl6dzx+/2
81KMZnJcji21rFN7XV7oPcNNq++p6E96zNmJZ/ECgYAxGmFG6lsuLc2JsmHRZS6k
SsdxfEeKpMKGhNozE4bratNOMiq5oA/kPsX15MMf1vtMRgYnWYG0Y2OAr7aBbsiC
7Rbeus2ax5q2m33PQSyp7yVjOUPste9SmSXxeizzDVTVEDBUfwasgsk88SdH7RPd
DManTY7vjcvzMOZKAvWcug==
-----END PRIVATE KEY-----"""

RSA_PUBLIC_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnCsLvq4lBBNi66ZN2A1j
BQS+ISExr/oM2fYUuIJ4vHGrGp93RUTYXROviswXBGDNckeJZRrr6/Ps3CnLu9Bp
aGPT5bPgBG2LMsUI1oldyMZC3+qDiKKD7HdHWyTxcMxcyjpgOamLwni86cSBFL9E
pyI1czcWzwdESzIBabw7MqE10CYKqrNANhL65iKV5C6hGVPrLUCVcvVH528n2h/x
Ymbbk8vdjop2KbcHdJA2u8cYbxOUQIPBZ1ehMCNd0Ez0BU7LN5NfltqFknTX/GJL
BqL6M91Zf55qRP6Jij2XYXE5KPfpwP+8JK11BO0MDED0+1mfIcCZ8Pcn5ZdcFMHr
HwIDAQAB
-----END PUBLIC KEY-----"""

EC_PRIVATE_PEM = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgh3P9zwNro7SElB6q
jr7LWhT8YDvQpzBVJDDMreMBKoGhRANCAAQOxGAkIYc1+dPwtMKUb5F3ABGK3nF2
0OrQZaf6iLOcXdj+JW85jyrKeneE0CUIfY5VTsd1Z068ZBjrylWo08/K
-----END PRIVATE KEY-----"""

EC_PUBLIC_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDsRgJCGHNfnT8LTClG+RdwARit5x
dtDq0GWn+oiznF3Y/iVvOY8qynp3hNAlCH2OVU7HdWdOvGQY68pVqNPPyg==
-----END PUBLIC KEY-----"""


def bench(name, alg, private_pem, public_pem, clasp_from_pem):
    token = jose_jwt.encode(
        {"sub": "bench", "exp": 4_102_444_800}, private_pem, algorithm=alg
    )
    assert jose_jwt.decode(token, public_pem, algorithms=[alg])["sub"] == "bench"
    key = clasp_from_pem(public_pem.encode(), alg)
    assert "bench" in key.verify(token)

    t0 = time.perf_counter()
    for _ in range(N):
        jose_jwt.decode(token, public_pem, algorithms=[alg])
    elapsed_jose = time.perf_counter() - t0

    t0 = time.perf_counter()
    for _ in range(N):
        key.verify(token)
    elapsed_clasp = time.perf_counter() - t0

    throughput_jose = N / elapsed_jose
    throughput_clasp = N / elapsed_clasp
    print(f"\n{name} ({alg}):")
    print(f"  python-jose (default pure-Python backend): {throughput_jose:,.0f}/sec")
    print(f"  Clasp:                                      {throughput_clasp:,.0f}/sec")
    print(f"  Speedup: {throughput_clasp / throughput_jose:.2f}x")


print(f"N = {N} per comparison")
bench("RSA", "RS256", RSA_PRIVATE_PEM, RSA_PUBLIC_PEM, clasp.AsymmetricKey.from_rsa_pem)
bench("EC", "ES256", EC_PRIVATE_PEM, EC_PUBLIC_PEM, clasp.AsymmetricKey.from_ec_pem)
