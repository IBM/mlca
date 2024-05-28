# MLCA

This projects contains implementations and tests for Module-Lattice Cryptographic Algorithms (MLCA).

## Algorithms

- Dilithium (NIST PQC round 2 and 3)
- Kyber (NIST PQC round 2 and 3)

The following variants are available:
- Dilithium2, Dilithium3, Dilithium5 (Round 3)
- Dilithium5x4, Dilithium6x5, Dilithium8x7 (Round 2)
- Kyber768, Kyber1024 (Round 2 and Round 3)

## Requirements

- Cmake (version 3.5 or later)
- C99-compatible compiler
- Valgrind (for dynamic testing)
- Clang static analyzer (version 10 or later, for static analysis)
- On s390x: GCC 11 or greater, Clang 11 or greater, for constant-time testing: Valgrind 3.18 or greater

## Build

- `mkdir -p build`
- `cd build`
- `cmake ..`
- `make`

The following files are available after `make` (in folder `build`):
- `libmlca.a`: MLCA static library
- `libmlca_shared.so`: MLCA shared library
- `libmlcaencoding.a`: MLCA encoding library
- `libmlcaencoding_shared.so`: MLCA encoding shared library
- `test/mlca_test`: Executable for test harness

To install the libraries and headers, use `cmake --install . --prefix "/home/myuser/installdir"`.

To clean a build do a `make clean` inside the build folder.

## Tests

The following tests are available: NIST KAT, Chained KAT, random self-tests, constant-time tests and performance tests.

To run the complete test harness, run `ctest`.

### NIST KAT

NIST KAT tests are built as part of `make` as part of the `mlca_test` harness, the corresponding KAT references are available in folder `KAT`.

The executable should be run from folder `test` to allow the KAT files to be found (relative to `build`):

- `ctest <alg_name>-kat_nist`

### Chain KAT

Chain KAT are a flexible form of KAT. They chain together one or more test cases where the seed of each new test depends on the result of the previous test. This allows to either test a full test set or any subset of the full test.
A chain KAT is identifiable with a compact representation only containing three entries:
- seed: initial seed for the PRNG
- count: number of tests
- shake256-384: hash value (SHAKE256-384) of the last test

Chain KAT tests are built as part of `make` as part of the `mlca_test` harness, the corresponding KAT references are available in folder `KAT` with suffix `.shake256`.

The executable should be run from folder `test` to allow the KAT files to be found (relative to `build`):

- `ctest <alg_name>-kat_chain`

### Self-tests
Randomized self-tests for KEM and Signature schemes can run individually with the following command:

- `ctest <alg_name>-self`

### Constant-time tests
Constant-time tests check if any conditional branches or jumps occur that depend on secret data. The used method is also known as TIMECOP.
The test harness needs to be executed with valgrind:

- `valgrind --tool=memcheck --gen-suppressions=all ./test/mlca_test <alg_name> self_const`

There are instances of non-constant time behavior that is justified. These occurences must be documented in so-called suppression files, which filter the false alerts in the constant time tests. The suppression file delivered in the test suite is available under `test/ct-passes`. To run valgrind with the suppression file:

- `valgrind --tool=memcheck --gen-suppressions=all --error-exitcode=1 --suppressions=../test/ct-passes test/mlca_test <alg_name> self_const`

### Static analysis
Static analysis with clang-analyzer is supported with several build options.

- Address Sanitizer (ASAN): `-DCMAKE_BUILD_TYPE=asan`
- Leak Sanitizer (LSAN): `-DCMAKE_BUILD_TYPE=lsan`
- Memory Sanitizer (MSAN): `-DCMAKE_BUILD_TYPE=msan`
- Undefined Behavior Sanitizer (UBSan): `-DCMAKE_BUILD_TYPE=ubsan`

### Performance tests
Performance tests with `<rep>` repetitions are available with the following command (relative to `build`):

- `./test/mlca_test <alg_name> speed <rep>`

### OQS interoperability tests
Tests interoperability with [libOQS](https://github.com/open-quantum-safe/liboqs). Tests are turned off by default and can be enabled by providing the cmake option `-DMLCA_OQS_INTEROP_TEST=ON`.

## API
MLCA contains a public API that allows to use QSC KEM and Signature schemes in an algorithm-independent way.

The public API and its documentation is available by including `mlca2.h`.

## Minimal version

A minimal version of MLCA can be compiled using only `qsc/crystals/mlca.c` and the dependencies in `qsc/crystals`.
Use `-DMLCA_MINIMAL` to avoid dependencies and `-DNO_MLCA_RANDOM` to avoid dependencies to the MLCA default random number generator.

## Directory structure
* `src`: MLCA level source files
* `include`: Public header files
* `KAT`: Known-Answer Test reference files
* `qsc`: QSC algorithm-related files
* `common`: common code and RNG
* `test`: Test harness
