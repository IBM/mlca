add_executable(mlca_test test.c test_extras.c test_extras.h test_kat.c test_chain_kat_gen.c test_kem.c test_sig.c test_constant.c)
add_executable(mlca_acvp_kem test_acvp_kem.c)
add_executable(mlca_acvp_sig test_acvp_sig.c)

target_link_libraries(mlca_test mlca mlcaencoding)
target_link_libraries(mlca_acvp_kem mlca mlcaencoding)
target_link_libraries(mlca_acvp_sig mlca mlcaencoding)

add_executable(mlca_test_keccak test_keccak.c test_extras.c)

target_link_libraries(mlca_test_keccak mlca mlcaencoding)

if (1)
add_test(Kyber768_R2-self mlca_test Kyber768_R2 self)
add_test(Kyber768_R2-self_encodings mlca_test Kyber768_R2 self_encodings)
add_test(Kyber768_R2-self_encodings_minimal mlca_test Kyber768_R2 self_encodings_minimal)
add_test(Kyber768_R2-kat_nist mlca_test Kyber768_R2 kat_nist)
add_test(Kyber768_R2-kat_chain mlca_test Kyber768_R2 kat_chain)
#add_test(Kyber768_R2-kat_chain_gen mlca_test Kyber768_R2 kat_chain_gen)

add_test(Kyber1024_R2-self mlca_test Kyber1024_R2 self)
add_test(Kyber1024_R2-self_encodings mlca_test Kyber1024_R2 self_encodings)
add_test(Kyber1024_R2-self_encodings_minimal mlca_test Kyber1024_R2 self_encodings_minimal)
add_test(Kyber1024_R2-kat_nist mlca_test Kyber1024_R2 kat_nist)
add_test(Kyber1024_R2-kat_chain mlca_test Kyber1024_R2 kat_chain)
#add_test(Kyber1024_R2-kat_chain_gen mlca_test Kyber1024_R2 kat_chain_gen)

add_test(Kyber768-self mlca_test Kyber768 self)
add_test(Kyber768-self_encodings mlca_test Kyber768 self_encodings)
#add_test(Kyber768-self_encodings_minimal mlca_test Kyber768 self_encodings_minimal) # not supported
add_test(Kyber768-kat_nist mlca_test Kyber768 kat_nist)
add_test(Kyber768-kat_chain mlca_test Kyber768 kat_chain)
#add_test(Kyber768-kat_chain_gen mlca_test Kyber768 kat_chain_gen)

add_test(Kyber1024-self mlca_test Kyber1024 self)
add_test(Kyber1024-self_encodings mlca_test Kyber1024 self_encodings)
#add_test(Kyber1024-self_encodings_minimal mlca_test Kyber1024 self_encodings_minimal) # not supported
add_test(Kyber1024-kat_nist mlca_test Kyber1024 kat_nist)
add_test(Kyber1024-kat_chain mlca_test Kyber1024 kat_chain)
#add_test(Kyber1024-kat_chain_gen mlca_test Kyber1024 kat_chain_gen)

add_test(ML-KEM-768-self mlca_test ML-KEM-768 self)
add_test(ML-KEM-768-kat_nist mlca_test ML-KEM-768 kat_nist)
add_test(ML-KEM-1024-self mlca_test ML-KEM-1024 self)
add_test(ML-KEM-1024-kat_nist mlca_test ML-KEM-1024 kat_nist)

endif()

add_test(Dilithium2-self mlca_test Dilithium2 self)
add_test(Dilithium3-self mlca_test Dilithium3 self)
add_test(Dilithium5-self mlca_test Dilithium5 self)
add_test(Dilithium54_R2-self mlca_test Dilithium54_R2 self)
add_test(Dilithium65_R2-self mlca_test Dilithium65_R2 self)
add_test(Dilithium87_R2-self mlca_test Dilithium87_R2 self)
add_test(ML-DSA-44-self mlca_test ML-DSA-44 self)
add_test(ML-DSA-65-self mlca_test ML-DSA-65 self)
add_test(ML-DSA-87-self mlca_test ML-DSA-87 self)

add_test(Dilithium2-self_encodings mlca_test Dilithium2 self_encodings)
add_test(Dilithium3-self_encodings mlca_test Dilithium3 self_encodings)
add_test(Dilithium5-self_encodings mlca_test Dilithium5 self_encodings)
add_test(Dilithium2-self_encodings_minimal mlca_test Dilithium2 self_encodings_minimal)
add_test(Dilithium3-self_encodings_minimal mlca_test Dilithium3 self_encodings_minimal)
add_test(Dilithium5-self_encodings_minimal mlca_test Dilithium5 self_encodings_minimal)

add_test(Dilithium54_R2-self_encodings_minimal mlca_test Dilithium54_R2 self_encodings_minimal)
add_test(Dilithium65_R2-self_encodings_minimal mlca_test Dilithium65_R2 self_encodings_minimal)
add_test(Dilithium87_R2-self_encodings_minimal mlca_test Dilithium87_R2 self_encodings_minimal)

add_test(Dilithium2-kat_nist mlca_test Dilithium2 kat_nist)
add_test(Dilithium3-kat_nist mlca_test Dilithium3 kat_nist)
add_test(Dilithium5-kat_nist mlca_test Dilithium5 kat_nist)
add_test(Dilithium54_R2-kat_nist mlca_test Dilithium54_R2 kat_nist)
add_test(Dilithium65_R2-kat_nist mlca_test Dilithium65_R2 kat_nist)
add_test(ML-DSA-44-kat_nist mlca_test ML-DSA-44 kat_nist)
add_test(ML-DSA-65-kat_nist mlca_test ML-DSA-65 kat_nist)
add_test(ML-DSA-87-kat_nist mlca_test ML-DSA-87 kat_nist)

add_test(Dilithium2-kat_chain mlca_test Dilithium2 kat_chain)
add_test(Dilithium3-kat_chain mlca_test Dilithium3 kat_chain)
add_test(Dilithium5-kat_chain mlca_test Dilithium5 kat_chain)
add_test(Dilithium54_R2-kat_chain mlca_test Dilithium54_R2 kat_chain)
add_test(Dilithium65_R2-kat_chain mlca_test Dilithium65_R2 kat_chain)
add_test(Dilithium87_R2-kat_chain mlca_test Dilithium87_R2 kat_chain)

add_test(SHA3-256 mlca_test_keccak SHA3-256)
add_test(SHA3-512 mlca_test_keccak SHA3-512)

OPTION(MLCA_OQS_INTEROP_TEST "OQS Interop test" OFF)
OPTION(MLCA_NO_VALGRIND "No valgrind available" ON)

if (MLCA_OQS_INTEROP_TEST)
    add_subdirectory(oqs-interop)
endif()

if (MLCA_NO_VALGRIND)
    add_definitions(-DMLCA_NO_VALGRIND=1)
endif()