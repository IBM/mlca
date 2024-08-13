# SPDX-License-Identifier: MIT

import os
import pytest
import re
import sys
import json

fips_kem = ["ML-KEM-768", "ML-KEM-1024"]
fips_sig = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]

ml_kem_encdec = "ACVP_Vectors/ML-KEM-encapDecap-FIPS203/internalProjection.json"
ml_kem_kg     = "ACVP_Vectors/ML-KEM-keyGen-FIPS203/internalProjection.json"

ml_dsa_kg     = "ACVP_Vectors/ML-DSA-keyGen-FIPS204/internalProjection.json"
ml_dsa_sig    = "ACVP_Vectors/ML-DSA-sigGen-FIPS204/internalProjection.json"
ml_dsa_ver    = "ACVP_Vectors/ML-DSA-sigVer-FIPS204/internalProjection.json"

@pytest.mark.parametrize('kem_name', fips_kem)
def test_acvp_vec_kem_keygen(kem_name):
    print("Here")
    if not(kem_name in fips_kem): pytest.skip("Not supported")

    with open(os.path.join('test', ml_kem_kg), 'r') as fp:
        ml_kem_kg_acvp  = json.load(fp)

        variantFound = False
        for variant in ml_kem_kg_acvp["testGroups"]:
            if variant["parameterSet"] == kem_name:
                variantFound = True
                for testCase in variant["tests"]:
                    d = testCase["d"]
                    z = testCase["z"]
                    pk = testCase["ek"]
                    sk = testCase["dk"]
                    
                    run_subprocess(
                        ['build/test/mlca_acvp_kem', kem_name, "keyGen", d+z, pk, sk]
                    )

        assert(variantFound == True)


@pytest.mark.parametrize('kem_name', fips_kem)
def test_acvp_vec_kem_encdec_aft(kem_name):

    if not(kem_name in fips_kem): pytest.skip("Not supported")

    with open(os.path.join('test', ml_kem_encdec), 'r') as fp:
        ml_kem_encdec_acvp  = json.load(fp)

        variantFound = False
        for variant in ml_kem_encdec_acvp["testGroups"]:
            if variant["parameterSet"] == kem_name and variant["testType"] == "AFT":
                variantFound = True
                for testCase in variant["tests"]:
                    #prompt
                    pk = testCase["ek"]
                    # TODO: need dk?
                    m = testCase["m"]
                    #expected results
                    k = testCase["k"]
                    c = testCase["c"]
                                        
                    run_subprocess(
                        ['build/test/mlca_acvp_kem', kem_name, "encDecAFT", m, pk, k, c]
                    )

        assert(variantFound == True)


@pytest.mark.parametrize('kem_name', fips_kem)
def test_acvp_vec_kem_encdec_val(kem_name):

    if not(kem_name in fips_kem): pytest.skip("Not supported")

    with open(os.path.join('test', ml_kem_encdec), 'r') as fp:
        ml_kem_encdec_acvp  = json.load(fp)

        variantFound = False
        for variant in ml_kem_encdec_acvp["testGroups"]:
            if variant["parameterSet"] == kem_name and variant["testType"] == "VAL":
                variantFound = True
                sk = variant["dk"]
                for testCase in variant["tests"]:
                    #prompt
                    c = testCase["c"]
                    #expected results
                    k = testCase["k"]
                                        
                    run_subprocess(
                        ['build/test/mlca_acvp_kem', kem_name, "encDecVAL", sk, k, c]
                    )

        assert(variantFound == True)

@pytest.mark.parametrize('sig_name', fips_sig)
def test_acvp_vec_sig_keygen(sig_name):

    if not(sig_name in fips_sig): pytest.skip("Not supported")

    with open(os.path.join('test', ml_dsa_kg), 'r') as fp:
        ml_sig_kg_acvp  = json.load(fp)

        variantFound = False
        for variant in ml_sig_kg_acvp["testGroups"]:
            if variant["parameterSet"] == sig_name:
                variantFound = True
                for testCase in variant["tests"]:
                    seed = testCase["seed"]
                    pk = testCase["pk"]
                    sk = testCase["sk"]
                    
                    run_subprocess(
                        ['build/test/mlca_acvp_sig', sig_name, "keyGen", seed, pk, sk]
                    )

        assert(variantFound == True)

@pytest.mark.parametrize('sig_name', fips_sig)
def test_acvp_vec_sig_gen_deterministic(sig_name):

    if not(sig_name in fips_sig): pytest.skip("Not supported")

    with open(os.path.join('test', ml_dsa_sig), 'r') as fp:
        ml_sig_sig_acvp  = json.load(fp)

        variantFound = False
        for variant in ml_sig_sig_acvp["testGroups"]:
            if variant["parameterSet"] == sig_name and variant["deterministic"] == True:
                variantFound = True
                for testCase in variant["tests"]:
                    sk = testCase["sk"]
                    message = testCase["message"]
                    signature = testCase["signature"]
                    run_subprocess(
                        ['build/test/mlca_acvp_sig', sig_name, "sigGen_det", sk, message, signature]
                    )

        assert(variantFound == True)

@pytest.mark.parametrize('sig_name', fips_sig)
def test_acvp_vec_sig_gen_randomized(sig_name):

    if not(sig_name in fips_sig): pytest.skip("Not supported")

    with open(os.path.join('test', ml_dsa_sig), 'r') as fp:
        ml_sig_sig_acvp  = json.load(fp)

        variantFound = False
        for variant in ml_sig_sig_acvp["testGroups"]:
            if variant["parameterSet"] == sig_name and variant["deterministic"] == False:
                variantFound = True
                for testCase in variant["tests"]:
                    sk = testCase["sk"]
                    message = testCase["message"]
                    signature = testCase["signature"]
                    rnd = testCase["rnd"]
                    
                    run_subprocess(
                        ['build/test/mlca_acvp_sig', sig_name, "sigGen_rnd", sk, message, signature, rnd]
                    )

        assert(variantFound == True)


@pytest.mark.parametrize('sig_name', fips_sig)
def test_acvp_vec_sig_ver(sig_name):
    print("Here")
    if not(sig_name in fips_sig): pytest.skip("Not supported")

    with open(os.path.join('test', ml_dsa_ver), 'r') as fp:
        ml_sig_sig_acvp  = json.load(fp)

        variantFound = False
        for variant in ml_sig_sig_acvp["testGroups"]:
            if variant["parameterSet"] == sig_name:
                variantFound = True
                pk = variant["pk"]
                for testCase in variant["tests"]:
                    message = testCase["message"]
                    signature = testCase["signature"]
                    testPassed = "1" if testCase["testPassed"] else "0"
                    
                    run_subprocess(
                        ['build/test/mlca_acvp_sig', sig_name, "sigVer", pk, message, signature, testPassed]
                    )

        assert(variantFound == True)

if __name__ == "__main__":
    import sys
    pytest.main(sys.argv)

import subprocess

def run_subprocess(command, working_dir='.', env=None, expected_returncode=0, input=None, ignore_returncode=False):
    """
    Helper function to run a shell command and report success/failure
    depending on the exit status of the shell command.
    """
    env_ = os.environ.copy()
    if env is not None:
        env_.update(env)
    env = env_

    # Note we need to capture stdout/stderr from the subprocess,
    # then print it, which pytest will then capture and
    # buffer appropriately
    print(working_dir + " > " + " ".join(command))

    result = subprocess.run(
            command,
            input=input,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=working_dir,
            env=env,
        )

    if not(ignore_returncode) and (result.returncode != expected_returncode):
        print(result.stdout.decode('utf-8'))
        assert False, "Got unexpected return code {}".format(result.returncode)
    return result.stdout.decode('utf-8')
