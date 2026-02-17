# SPDX-License-Identifier: Apache-2.0

"""Wycheproof vectors for ML-DSA and ML-KEM.

Executable paths default to build/test and can be overridden with MLCA_SIG_EXE
and MLCA_KEM_EXE (CTest supplies the targets from the current build).

Messages are domain-separated here for the internal ML-DSA API. Contexts longer
than 255 bytes, mu-only signing, and malformed private-key coefficients remain
explicit pytest skips: the current API does not expose these input checks or
operations. Fixed-size key/seed/ciphertext lengths are checked by the C harness;
wrong signature lengths and noncanonical ML-KEM keys reach the library itself.
Exit status 2 means input rejection, distinct from comparison/runtime failure.
"""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

_TEST_DIR = Path(__file__).resolve().parent
_VECTOR_DIR = _TEST_DIR / "Wycheproof_Vectors"
_SIG_EXE = os.environ.get(
    "MLCA_SIG_EXE", str(_TEST_DIR.parent / "build/test/mlca_acvp_sig")
)
_KEM_EXE = os.environ.get(
    "MLCA_KEM_EXE", str(_TEST_DIR.parent / "build/test/mlca_acvp_kem")
)
_INPUT_REJECTED = 2
_SIG_ALGS = {
    "mldsa_44": "ML-DSA-44",
    "mldsa_65": "ML-DSA-65",
    "mldsa_87": "ML-DSA-87",
}
_KEM_ALGS = {
    "mlkem_768": "ML-KEM-768",
    "mlkem_1024": "ML-KEM-1024",
}


def _cases(algorithms, suffix):
    for prefix, algorithm in algorithms.items():
        with (_VECTOR_DIR / f"{prefix}_{suffix}.json").open() as fp:
            data = json.load(fp)
        assert sum(len(g["tests"]) for g in data["testGroups"]) == data["numberOfTests"]
        for group_index, group in enumerate(data["testGroups"]):
            for case in group["tests"]:
                yield pytest.param(
                    algorithm, group, case,
                    id=f"{algorithm}-g{group_index}-tc{case['tcId']}"
                )


def run_subprocess(command, expected_returncode=0):
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=60,
    )
    assert result.returncode == expected_returncode, (
        f"{command[1:3]}: expected exit {expected_returncode}, got {result.returncode}\n"
        f"{result.stdout}"
    )
    return result.stdout


def _compute_msg_prime(case):
    if "Internal" in case.get("flags", []):
        pytest.skip("ML-DSA API does not accept precomputed mu")
    context = case.get("ctx", "")
    if len(context) // 2 > 255:
        pytest.skip("ML-DSA API has no context parameter to test overlong-context rejection")
    return "00" + format(len(context) // 2, "02x") + context + case["msg"]


@pytest.mark.parametrize("algorithm,group,case", _cases(_SIG_ALGS, "verify_test"))
def test_wycheproof_mldsa_verify(algorithm, group, case):
    msg = _compute_msg_prime(case)
    expected = _INPUT_REJECTED if "IncorrectPublicKeyLength" in case["flags"] else 0
    run_subprocess(
        [_SIG_EXE, algorithm, "sigVer", group["publicKey"], msg,
         case["sig"], "1" if case["result"] == "valid" else "0"], expected
    )


@pytest.mark.parametrize("algorithm,group,case", _cases(_SIG_ALGS, "sign_noseed_test"))
def test_wycheproof_mldsa_sign_noseed(algorithm, group, case):
    if "InvalidPrivateKey" in case["flags"]:
        pytest.skip("ML-DSA API assumes a validated expanded private key")
    msg = _compute_msg_prime(case)
    expected = _INPUT_REJECTED if case["result"] == "invalid" else 0
    run_subprocess(
        [_SIG_EXE, algorithm, "sigGen_det", group["privateKey"], msg, case["sig"]], expected
    )


@pytest.mark.parametrize("algorithm,group,case", _cases(_SIG_ALGS, "sign_seed_test"))
def test_wycheproof_mldsa_sign_seed(algorithm, group, case):
    msg = _compute_msg_prime(case)
    run_subprocess(
        [_SIG_EXE, algorithm, "sigGenFromSeed", group["privateSeed"], msg, case["sig"]]
    )


@pytest.mark.parametrize("algorithm,group,case", _cases(_KEM_ALGS, "encaps_test"))
def test_wycheproof_mlkem_encaps(algorithm, group, case):
    if case["result"] == "invalid":
        run_subprocess(
            [_KEM_EXE, algorithm, "encReject", case["m"], case["ek"]], _INPUT_REJECTED
        )
    else:
        run_subprocess(
            [_KEM_EXE, algorithm, "encDecAFT", case["m"], case["ek"], case["K"], case["c"]]
        )


@pytest.mark.parametrize("algorithm,group,case", _cases(_KEM_ALGS, "keygen_seed_test"))
def test_wycheproof_mlkem_keygen(algorithm, group, case):
    assert case["result"] == "valid"
    run_subprocess(
        [_KEM_EXE, algorithm, "keyGen", case["seed"], case["ek"], case["dk"]]
    )


@pytest.mark.parametrize("algorithm,group,case", _cases(_KEM_ALGS, "test"))
def test_wycheproof_mlkem_decaps(algorithm, group, case):
    expected = _INPUT_REJECTED if case["result"] == "invalid" else 0
    run_subprocess(
        [_KEM_EXE, algorithm, "decFromSeed", case["seed"], case.get("ek", ""),
         case["K"], case["c"]], expected
    )


@pytest.mark.parametrize("algorithm", _SIG_ALGS.values())
@pytest.mark.parametrize("seed_length", [0, 1, 31, 33, 64])
def test_wycheproof_seed_length(algorithm, seed_length):
    # Supply otherwise valid arguments so only seed-length validation can reject.
    prefix = next(p for p, a in _SIG_ALGS.items() if a == algorithm)
    with (_VECTOR_DIR / f"{prefix}_sign_seed_test.json").open() as fp:
        case = json.load(fp)["testGroups"][0]["tests"][0]
    run_subprocess(
        [_SIG_EXE, algorithm, "sigGenFromSeed", "00" * seed_length,
         _compute_msg_prime(case), case["sig"]], _INPUT_REJECTED
    )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, *sys.argv[1:]]))
