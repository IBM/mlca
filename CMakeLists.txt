cmake_minimum_required(VERSION 3.5)
project(mlca_framework LANGUAGES C ASM VERSION 0.1.0)

set(CMAKE_C_STANDARD 99)
#set(CMAKE_BUILD_TYPE Release)
set(CMAKE_C_FLAGS_RELEASE "-Werror=vla -Wunused-function -O3")
#set(CMAKE_C_FLAGS_DEBUG "-Werror=vla -Wunused-function")

# AddressSanitizer
set(CMAKE_C_FLAGS_ASAN
    "-fsanitize=address -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1"
    CACHE STRING "Flags used by the C compiler during AddressSanitizer builds."
    FORCE)
set(CMAKE_CXX_FLAGS_ASAN
    "-fsanitize=address -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1"
    CACHE STRING "Flags used by the C++ compiler during AddressSanitizer builds."
    FORCE)

# LeakSanitizer
set(CMAKE_C_FLAGS_LSAN
    "-fsanitize=leak -fno-omit-frame-pointer -g -O1"
    CACHE STRING "Flags used by the C compiler during LeakSanitizer builds."
    FORCE)
set(CMAKE_CXX_FLAGS_LSAN
    "-fsanitize=leak -fno-omit-frame-pointer -g -O1"
    CACHE STRING "Flags used by the C++ compiler during LeakSanitizer builds."
    FORCE)

# MemorySanitizer
set(CMAKE_C_FLAGS_MSAN
    "-fsanitize=memory -fno-optimize-sibling-calls -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -g -O2"
    CACHE STRING "Flags used by the C compiler during MemorySanitizer builds."
    FORCE)
set(CMAKE_CXX_FLAGS_MSAN
    "-fsanitize=memory -fno-optimize-sibling-calls -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -g -O2"
    CACHE STRING "Flags used by the C++ compiler during MemorySanitizer builds."
    FORCE)

# UndefinedBehaviour
set(CMAKE_C_FLAGS_UBSAN
    "-fsanitize=undefined"
    CACHE STRING "Flags used by the C compiler during UndefinedBehaviourSanitizer builds."
    FORCE)
set(CMAKE_CXX_FLAGS_UBSAN
    "-fsanitize=undefined"
    CACHE STRING "Flags used by the C++ compiler during UndefinedBehaviourSanitizer builds."
    FORCE)

# Coverage
set(CMAKE_C_FLAGS_COVERAGE
    "-fprofile-arcs -ftest-coverage"
    CACHE STRING "Flags used by the C compiler during Coverage builds."
    FORCE)

# CT-testing configs
set(CMAKE_C_FLAGS_CTOS
    "-Os -gdwarf-4"
    CACHE STRING "Flags used by the C compiler during CT builds."
    FORCE)

set(CMAKE_C_FLAGS_CTO0
    "-O0 -gdwarf-4"
    CACHE STRING "Flags used by the C compiler during CT builds."
    FORCE)

set(CMAKE_C_FLAGS_CTO1
    "-O1 -gdwarf-4"
    CACHE STRING "Flags used by the C compiler during CT builds."
    FORCE)

set(CMAKE_C_FLAGS_CTO2
    "-O2 -gdwarf-4"
    CACHE STRING "Flags used by the C compiler during CT builds."
    FORCE)

set(CMAKE_C_FLAGS_CTO3
    "-O3 -gdwarf-4"
    CACHE STRING "Flags used by the C compiler during CT builds."
    FORCE)

set(CMAKE_C_FLAGS_CTOSNOVEC
    "-Os -fno-vectorize -gdwarf-4"
    CACHE STRING "Flags used by the C compiler during CT builds."
    FORCE)

set(CMAKE_C_FLAGS_CTO0NOVEC
    "-O0 -fno-vectorize -gdwarf-4"
    CACHE STRING "Flags used by the C compiler during CT builds."
    FORCE)

set(CMAKE_C_FLAGS_CTO1NOVEC
    "-O1 -fno-vectorize -gdwarf-4"
    CACHE STRING "Flags used by the C compiler during CT builds."
    FORCE)

set(CMAKE_C_FLAGS_CTO2NOVEC
    "-O2 -fno-vectorize -gdwarf-4"
    CACHE STRING "Flags used by the C compiler during CT builds."
    FORCE)

set(CMAKE_C_FLAGS_CTO3NOVEC
    "-O3 -fno-vectorize -gdwarf-4"
    CACHE STRING "Flags used by the C compiler during CT builds."
    FORCE)

set(
    LIBRARY_FILES
    include/mlca2.h src/mlca2.c
    qsc/crystals/keccak.h qsc/crystals/keccak.c
    common/random_default.h
    src/mlca_crystals_kyber.c src/mlca_crystals_dilithium.c
    qsc/crystals/mlca.c qsc/crystals/pqalgs.h qsc/crystals/crystals-oids.h qsc/crystals/polyvec-include.h
)

set (
    LIBRARY_ENCODING_FILES
    encoding/encoding_kyber.c encoding/encoding_dilithium.c
    encoding/mlca_asn1.c
)

set(
    LIBRARY_PLATFORM_FILES
)

set(OS_UNIX 1)
set(OS_OTHER 2)

if (UNIX)
    add_definitions(-DOS_TARGET=${OS_UNIX})
else()
    add_definitions(-DOS_TARGET=${OS_OTHER})
endif()

set(TARGET_ARM64 1)
set(TARGET_ARM 2)
set(TARGET_AMD64 3)
set(TARGET_x86 4)
set(TARGET_S390X 5)
set(TARGET_MIPS64 6)
set(TARGET_OTHER 7)

if (TARGET_PLATFORM)
    if(${TARGET_PLATFORM} MATCHES "aarch64")
        add_definitions(-DTARGET_PLATFORM=${TARGET_ARM64})
        add_definitions(-DTARGET_DYNFREQ=1)
    elseif(${TARGET_PLATFORM} MATCHES "arm")
        add_definitions(-DTARGET_PLATFORM=${TARGET_ARM})
        add_definitions(-DTARGET_DYNFREQ=1)
    elseif(${TARGET_PLATFORM} MATCHES "x86_64")
        add_definitions(-DTARGET_PLATFORM=${TARGET_AMD64})
        add_definitions(-DTARGET_DYNFREQ=1)
    elseif(${TARGET_PLATFORM} MATCHES "i386" OR ${CMAKE_SYSTEM_PROCESSOR} MATCHES "i686")
        add_definitions(-DTARGET_PLATFORM=${TARGET_x86})
        add_definitions(-DTARGET_DYNFREQ=1)
    elseif(${TARGET_PLATFORM} MATCHES "^(s390x.*|S390X.*)")
        add_definitions(-DTARGET_PLATFORM=${TARGET_S390X})
    elseif(${TARGET_PLATFORM} MATCHES "mips64")
        add_definitions(-DTARGET_PLATFORM=${TARGET_MIPS64})
    else()
        add_definitions(-DTARGET_PLATFORM=${TARGET_OTHER})
    endif()
else()

    if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "aarch64")
        add_definitions(-DTARGET_PLATFORM=${TARGET_ARM64})
        add_definitions(-DTARGET_DYNFREQ=1)
    elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm")
        add_definitions(-DTARGET_PLATFORM=${TARGET_ARM})
        add_definitions(-DTARGET_DYNFREQ=1)
    elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64")
        add_definitions(-DTARGET_PLATFORM=${TARGET_AMD64})
        add_definitions(-DTARGET_DYNFREQ=1)
    elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "i386" OR ${CMAKE_SYSTEM_PROCESSOR} MATCHES "i686")
        add_definitions(-DTARGET_PLATFORM=${TARGET_x86})
        add_definitions(-DTARGET_DYNFREQ=1)
    elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "^(s390x.*|S390X.*)")
        add_definitions(-DTARGET_PLATFORM=${TARGET_S390X})
        add_compile_options(-march=z14 -mzvector -mvx)
    else()
        add_definitions(-DTARGET_PLATFORM=${TARGET_OTHER})
        add_definitions(-DTARGET_DYNFREQ=1)
    endif()
endif()

include_directories(include)
include_directories(qsc/crystals)

include_directories(common)

set (
        RANDOM_FILES
        common/random_system.c common/random_system.h
)

set(
        RANDOM_FILES_TEST
        common/random_ctrdrbg.h common/random_ctrdrbg.c
        common/aes.h common/aes_256_ecb.c
)

add_library(mlcaencoding STATIC ${LIBRARY_ENCODING_FILES})
add_library(mlcaencoding_shared SHARED ${LIBRARY_ENCODING_FILES})

add_library(mlca STATIC ${LIBRARY_FILES} ${LIBRARY_PLATFORM_FILES} ${RANDOM_FILES} ${RANDOM_FILES_TEST} ${LIBRARY_ENCODING_FILES})
add_library(mlca_shared SHARED ${LIBRARY_FILES} ${LIBRARY_PLATFORM_FILES} ${RANDOM_FILES} ${RANDOM_FILES_TEST} ${LIBRARY_ENCODING_FILES})

install(TARGETS mlca mlca_shared mlcaencoding mlcaencoding_shared DESTINATION lib)
install(FILES include/mlca2.h include/mlca2_random.h DESTINATION include)

enable_testing()

add_subdirectory(test)
