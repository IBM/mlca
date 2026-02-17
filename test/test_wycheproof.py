# SPDX-License-Identifier: Apache-2.0

"""
Wycheproof test-vector driver for mlca.

Parses Wycheproof JSON vectors from test/Wycheproof_Vectors/ and exercises
the existing mlca_acvp_sig / mlca_acvp_kem C executables through subprocess
calls — the same pattern used by test_acvp.py.

Vectors covered:
  ML-DSA  – verify, sign_noseed, sign_seed
  ML-KEM  – encaps, keygen_seed

Note on domain separation:
  The C executables call mlca_sig_{sign,verify}_internal() which works
  at the Sign_internal / Verify_internal level (FIPS 204 algorithms 7/8).
  Wycheproof non-Internal tests provide the external message M, so we
  must prepend the domain separator for pure mode before calling the
  internal primitive:  M' = 0x00 || len(ctx) || ctx || M.
  For empty context (all non-ctx tests): M' = 0x00 || 0x00 || M,
  i.e. we prepend "0000" to the hex message.

Vectors intentionally skipped (noted in each function):
  - ML-DSA sign tests with "Internal" flag (require mu-level API not exposed)
  - ML-DSA sign tests with "ctx" field (tested via verify instead)
  - ML-DSA sign tests with result "invalid" (empty expected sig)
  - ML-DSA verify tests with "IncorrectSignatureLength" (C-side length check)
  - ML-DSA verify tests with "IncorrectPublicKeyLength" (C-side length check)
  - ML-DSA verify tests with "InvalidContext" (context > 255 bytes)
  - ML-KEM encaps tests with result "invalid" (malformed inputs)
  - ML-KEM general tests (mlkem_*_test.json) — complex seed-based format
  - ML-KEM semi-expanded decaps tests — no expected K for comparison
"""

import json
import os
import subprocess
import sys

import pytest

# ---------------------------------------------------------------------------
# Algorithm lists
# ---------------------------------------------------------------------------
fips_sig = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
fips_kem = ["ML-KEM-768", "ML-KEM-1024"]

# Mapping from Wycheproof file-name convention to mlca algorithm name
_SIG_ALG_MAP = {
    "mldsa_44": "ML-DSA-44",
    "mldsa_65": "ML-DSA-65",
    "mldsa_87": "ML-DSA-87",
}
_KEM_ALG_MAP = {
    "mlkem_768":  "ML-KEM-768",
    "mlkem_1024": "ML-KEM-1024",
}

# Paths (relative to workspace root)
_VECTOR_DIR = os.path.join("test", "Wycheproof_Vectors")
_SIG_EXE    = os.path.join("build", "test", "mlca_acvp_sig")
_KEM_EXE    = os.path.join("build", "test", "mlca_acvp_kem")

# ---------------------------------------------------------------------------
# Subprocess helper  (mirrors test_acvp.py)
# ---------------------------------------------------------------------------
def run_subprocess(command, working_dir=".", expected_returncode=0):
    """Run *command* and assert its return code."""
    env = os.environ.copy()
    print(working_dir + " > " + " ".join(command))
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=working_dir,
        env=env,
    )
    if result.returncode != expected_returncode:
        print(result.stdout.decode("utf-8"))
        assert False, "Got unexpected return code {}".format(result.returncode)
    return result.stdout.decode("utf-8")

# ---------------------------------------------------------------------------
# Helper: compute M' = 0x00 || len(ctx) || ctx || M  (FIPS 204 domain separator)
# ---------------------------------------------------------------------------
def _compute_msg_prime(msg_hex, ctx_hex=None):
    """Prepend the pure-mode domain separator to the message.

    Returns the hex-encoded M' or None if the context is too long (>255 bytes).
    """
    if ctx_hex is None or ctx_hex == "":
        return "0000" + msg_hex
    ctx_byte_len = len(ctx_hex) // 2
    if ctx_byte_len > 255:
        return None  # context too long – can't encode in 1 byte
    return "00" + format(ctx_byte_len, "02x") + ctx_hex + msg_hex

# ---------------------------------------------------------------------------
# Helper: load a vector file
# ---------------------------------------------------------------------------
def _load_vectors(filename):
    path = os.path.join(_VECTOR_DIR, filename)
    with open(path, "r") as fp:
        return json.load(fp)


# ===================================================================
# ML-DSA  verify
# ===================================================================
@pytest.mark.parametrize("sig_name", fips_sig)
def test_wycheproof_mldsa_verify(sig_name):
    """
    Wycheproof ML-DSA verify vectors.

    Skips:
      - IncorrectSignatureLength (C-side hard length check)
      - IncorrectPublicKeyLength (C-side hard length check)
      - InvalidContext (context > 255 bytes, can't encode)
    """
    wp_prefix = {v: k for k, v in _SIG_ALG_MAP.items()}[sig_name]
    data = _load_vectors(f"{wp_prefix}_verify_test.json")

    tested = 0
    skipped = 0
    for group in data["testGroups"]:
        pk = group["publicKey"]
        for tc in group["tests"]:
            flags = tc.get("flags", [])

            # Skip vectors where the C executable does a hard length check
            # and would exit(1) before calling verify.
            if "IncorrectSignatureLength" in flags:
                skipped += 1
                continue
            if "IncorrectPublicKeyLength" in flags:
                skipped += 1
                continue

            msg = tc["msg"]
            sig = tc["sig"]
            ctx_hex = tc.get("ctx")  # may be absent, "", or hex string
            test_passed = "1" if tc["result"] == "valid" else "0"

            # Compute M' with the correct domain separator / context.
            msg_prime = _compute_msg_prime(msg, ctx_hex)
            if msg_prime is None:
                # Context too long (>255 bytes) – skip.
                skipped += 1
                continue

            run_subprocess(
                [_SIG_EXE, sig_name, "sigVer", pk, msg_prime, sig, test_passed]
            )
            tested += 1

    assert tested > 0, f"No verify vectors tested for {sig_name}"
    print(f"  [{sig_name}] tested {tested}, skipped {skipped}")


# ===================================================================
# ML-DSA  sign (noseed — full private key provided)
# ===================================================================
@pytest.mark.parametrize("sig_name", fips_sig)
def test_wycheproof_mldsa_sign_noseed(sig_name):
    """
    Wycheproof ML-DSA sign_noseed vectors.
    Tests deterministic signing with a provided full private key.

    Skips:
      - "Internal" flag (mu-only, no msg — needs deeper API)
      - tests with "ctx" field (requires external sign API with context)
      - result "invalid" (expected sig is empty)
    """
    wp_prefix = {v: k for k, v in _SIG_ALG_MAP.items()}[sig_name]
    data = _load_vectors(f"{wp_prefix}_sign_noseed_test.json")

    tested = 0
    skipped = 0
    for group in data["testGroups"]:
        sk = group["privateKey"]
        for tc in group["tests"]:
            flags = tc.get("flags", [])

            if "Internal" in flags:
                skipped += 1
                continue
            if "ctx" in tc:
                skipped += 1
                continue
            if tc["result"] != "valid":
                skipped += 1
                continue

            msg = tc["msg"]
            sig = tc["sig"]

            # Prepend pure-mode domain separator (empty ctx).
            msg_prime = _compute_msg_prime(msg)

            run_subprocess(
                [_SIG_EXE, sig_name, "sigGen_det", sk, msg_prime, sig]
            )
            tested += 1

    assert tested > 0, f"No sign_noseed vectors tested for {sig_name}"
    print(f"  [{sig_name}] tested {tested}, skipped {skipped}")


# ===================================================================
# ML-DSA  sign (seed — derive keypair from 32-byte seed)
# ===================================================================
@pytest.mark.parametrize("sig_name", fips_sig)
def test_wycheproof_mldsa_sign_seed(sig_name):
    """
    Wycheproof ML-DSA sign_seed vectors.
    Uses the sigGenFromSeed CLI mode: derives (pk,sk) from seed, then signs
    deterministically and compares to expected signature.

    Skips:
      - "Internal" flag (mu-only, no msg)
      - tests with "ctx" field
      - result "invalid" (empty sig)
    """
    wp_prefix = {v: k for k, v in _SIG_ALG_MAP.items()}[sig_name]
    data = _load_vectors(f"{wp_prefix}_sign_seed_test.json")

    tested = 0
    skipped = 0
    for group in data["testGroups"]:
        seed = group["privateSeed"]
        for tc in group["tests"]:
            flags = tc.get("flags", [])

            if "Internal" in flags:
                skipped += 1
                continue
            if "ctx" in tc:
                skipped += 1
                continue
            if tc["result"] != "valid":
                skipped += 1
                continue

            msg = tc["msg"]
            sig = tc["sig"]

            # Prepend pure-mode domain separator (empty ctx).
            msg_prime = _compute_msg_prime(msg)

            run_subprocess(
                [_SIG_EXE, sig_name, "sigGenFromSeed", seed, msg_prime, sig]
            )
            tested += 1

    assert tested > 0, f"No sign_seed vectors tested for {sig_name}"
    print(f"  [{sig_name}] tested {tested}, skipped {skipped}")


# ===================================================================
# ML-KEM  encapsulation
# ===================================================================
@pytest.mark.parametrize("kem_name", fips_kem)
def test_wycheproof_mlkem_encaps(kem_name):
    """
    Wycheproof ML-KEM encapsulation vectors.
    Only tests 'valid' results (invalid ones have empty c/K or bad ek).
    """
    wp_prefix = {v: k for k, v in _KEM_ALG_MAP.items()}[kem_name]
    data = _load_vectors(f"{wp_prefix}_encaps_test.json")

    tested = 0
    skipped = 0
    for group in data["testGroups"]:
        for tc in group["tests"]:
            if tc["result"] != "valid":
                skipped += 1
                continue

            m  = tc["m"]
            ek = tc["ek"]
            c  = tc["c"]
            K  = tc["K"]

            run_subprocess(
                [_KEM_EXE, kem_name, "encDecAFT", m, ek, K, c]
            )
            tested += 1

    assert tested > 0, f"No encaps vectors tested for {kem_name}"
    print(f"  [{kem_name}] tested {tested}, skipped {skipped}")


# ===================================================================
# ML-KEM  keygen from seed
# ===================================================================
@pytest.mark.parametrize("kem_name", fips_kem)
def test_wycheproof_mlkem_keygen(kem_name):
    """
    Wycheproof ML-KEM keygen-from-seed vectors.
    seed is 64 bytes (d || z), same format as ACVP keyGen.
    """
    wp_prefix = {v: k for k, v in _KEM_ALG_MAP.items()}[kem_name]
    data = _load_vectors(f"{wp_prefix}_keygen_seed_test.json")

    tested = 0
    skipped = 0
    for group in data["testGroups"]:
        for tc in group["tests"]:
            if tc["result"] != "valid":
                skipped += 1
                continue

            seed = tc["seed"]
            ek   = tc["ek"]
            dk   = tc["dk"]

            run_subprocess(
                [_KEM_EXE, kem_name, "keyGen", seed, ek, dk]
            )
            tested += 1

    assert tested > 0, f"No keygen vectors tested for {kem_name}"
    print(f"  [{kem_name}] tested {tested}, skipped {skipped}")


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    pytest.main(sys.argv)
