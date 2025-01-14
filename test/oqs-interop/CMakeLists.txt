add_executable(mlca_interop_test_oqs040 test_oqs_interop.c ../test_extras.c)
add_executable(mlca_interop_test_oqs0100 test_oqs_interop.c ../test_extras.c)
add_executable(mlca_interop_test_oqs0120 test_oqs_interop.c ../test_extras.c)

SET(LIB_HEADER_FOLDER_040 ${CMAKE_SOURCE_DIR}/test/oqs-interop/lib040/include)
SET(LIB_HEADER_FOLDER_0100 ${CMAKE_SOURCE_DIR}/test/oqs-interop/lib0100/include)
SET(LIB_HEADER_FOLDER_0120 ${CMAKE_SOURCE_DIR}/test/oqs-interop/lib0120/include)
SET(LIB_LIB_FOLDER_040 ${CMAKE_SOURCE_DIR}/test/oqs-interop/lib040/lib)
SET(LIB_LIB_FOLDER_0100 ${CMAKE_SOURCE_DIR}/test/oqs-interop/lib0100/lib)
SET(LIB_LIB_FOLDER_0120 ${CMAKE_SOURCE_DIR}/test/oqs-interop/lib0120/lib)
SET(LIB_FILE_040 ${CMAKE_SOURCE_DIR}/test/oqs-interop/lib040/lib/liboqs.a)
SET(LIB_FILE_0100 ${CMAKE_SOURCE_DIR}/test/oqs-interop/lib0100/lib/liboqs.a)
SET(LIB_FILE_0120 ${CMAKE_SOURCE_DIR}/test/oqs-interop/lib0120/lib/liboqs.a)

add_custom_command(
    OUTPUT ${LIB_FILE_040} ${LIB_FILE_0100} ${LIB_FILE_0120} ${LIB_LIB_FOLDER_040} ${LIB_LIB_FOLDER_0100} ${LIB_LIB_FOLDER_0120}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/test/oqs-interop
    COMMAND sh get_oqs.sh
)
add_custom_target(oqs040_target DEPENDS ${LIB_FILE_040} ${LIB_HEADER_FOLDER_040})
add_custom_target(oqs0100_target DEPENDS ${LIB_FILE_0100} ${LIB_HEADER_FOLDER_0100})
add_custom_target(oqs0120_target DEPENDS ${LIB_FILE_0120} ${LIB_HEADER_FOLDER_0120})

add_library(oqs040 STATIC IMPORTED)
add_dependencies(oqs040 oqs040_target)
set_target_properties(oqs040 PROPERTIES
  IMPORTED_LOCATION ${LIB_FILE_040}
  INTERFACE_INCLUDE_DIRECTORIES ${LIB_HEADER_FOLDER_040}
)

add_library(oqs0100 STATIC IMPORTED)
add_dependencies(oqs0100 oqs0100_target)
set_target_properties(oqs0100 PROPERTIES
  IMPORTED_LOCATION ${LIB_FILE_0100}
  INTERFACE_INCLUDE_DIRECTORIES ${LIB_HEADER_FOLDER_0100}
)

add_library(oqs0120 STATIC IMPORTED)
add_dependencies(oqs0120 oqs0120_target)
set_target_properties(oqs0120 PROPERTIES
  IMPORTED_LOCATION ${LIB_FILE_0120}
  INTERFACE_INCLUDE_DIRECTORIES ${LIB_HEADER_FOLDER_0120}
)

include_directories(${CMAKE_SOURCE_DIR}/test/oqs-interop/include)
link_directories(${CMAKE_SOURCE_DIR}/test/oqs-interop/lib)

target_link_libraries(mlca_interop_test_oqs040 mlca mlcaencoding oqs040)
target_link_libraries(mlca_interop_test_oqs0120 mlca mlcaencoding oqs0120)
target_link_libraries(mlca_interop_test_oqs0100 mlca mlcaencoding oqs0100)

add_test(ML-DSA-44-oqs0120interop mlca_interop_test_oqs0120 ML-DSA-44 oqs_interop)
add_test(ML-DSA-65-oqs0120interop mlca_interop_test_oqs0120 ML-DSA-65 oqs_interop)
add_test(ML-DSA-87-oqs0120interop mlca_interop_test_oqs0120 ML-DSA-87 oqs_interop)

add_test(Dilithium2-oqs0100interop mlca_interop_test_oqs0100 Dilithium2 oqs_interop)
add_test(Dilithium3-oqs0100interop mlca_interop_test_oqs0100 Dilithium3 oqs_interop)
add_test(Dilithium5-oqs0100interop mlca_interop_test_oqs0100 Dilithium5 oqs_interop)

add_test(ML-KEM-768-oqs0120interop mlca_interop_test_oqs0120 ML-KEM-768 oqs_interop)
add_test(ML-KEM-1024-oqs0120interop mlca_interop_test_oqs0120 ML-KEM-1024 oqs_interop)

add_test(Kyber768-oqs040interop mlca_interop_test_oqs040 Kyber768_R2 oqs_interop)
add_test(Kyber1024-oqs040interop mlca_interop_test_oqs040 Kyber1024_R2 oqs_interop)

add_test(Dilithium3-oqs040interop mlca_interop_test_oqs040 Dilithium54_R2 oqs_interop)
add_test(Dilithium4-oqs040interop mlca_interop_test_oqs040 Dilithium65_R2 oqs_interop)

add_test(Kyber768-oqs0100interop mlca_interop_test_oqs0100 Kyber768 oqs_interop)
add_test(Kyber1024-oqs0100interop mlca_interop_test_oqs0100 Kyber1024 oqs_interop)
