#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Downloads Wycheproof test vectors for ML-DSA and ML-KEM from
# https://github.com/C2SP/wycheproof

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="${SCRIPT_DIR}/Wycheproof_Vectors"
BASE_URL="https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1"

mkdir -p "${DEST_DIR}"

VECTORS=(
    # ML-DSA verify
    mldsa_44_verify_test.json
    mldsa_65_verify_test.json
    mldsa_87_verify_test.json
    # ML-DSA sign (with seed)
    mldsa_44_sign_seed_test.json
    mldsa_65_sign_seed_test.json
    mldsa_87_sign_seed_test.json
    # ML-DSA sign (without seed, full private key)
    mldsa_44_sign_noseed_test.json
    mldsa_65_sign_noseed_test.json
    mldsa_87_sign_noseed_test.json
    # ML-KEM general (encapsulation)
    mlkem_768_test.json
    mlkem_1024_test.json
    # ML-KEM encapsulation
    mlkem_768_encaps_test.json
    mlkem_1024_encaps_test.json
    # ML-KEM key generation from seed
    mlkem_768_keygen_seed_test.json
    mlkem_1024_keygen_seed_test.json
)

echo "Downloading Wycheproof vectors to ${DEST_DIR} ..."

for f in "${VECTORS[@]}"; do
    if [ -f "${DEST_DIR}/${f}" ]; then
        echo "  [skip] ${f} (already exists)"
    else
        echo "  [get]  ${f}"
        curl -sS -L -o "${DEST_DIR}/${f}" "${BASE_URL}/${f}"
    fi
done

echo "Done. Downloaded ${#VECTORS[@]} vector files."
