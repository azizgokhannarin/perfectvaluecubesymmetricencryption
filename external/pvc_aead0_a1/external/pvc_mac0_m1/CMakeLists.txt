cmake_minimum_required(VERSION 3.20)
project(perfectvaluecubemac VERSION 0.2.0 LANGUAGES CXX)

option(PVCMAC0_BUILD_TESTS "Build PVC-MAC-0 tests" ON)
option(PVCMAC0_BUILD_TOOLS "Build PVC-MAC-0 research tools" ON)
set(PVCMAC0_DIFFERENTIAL_CASES "4096" CACHE STRING "Differential cases used by CTest")

function(pvcmac0_apply_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive-)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
    endif()
endfunction()

set(PVC1_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/external/pvc_prf1_c1)
add_library(pvc_prf1_c1 STATIC
    ${PVC1_ROOT}/src/cube.cpp
    ${PVC1_ROOT}/src/controller.cpp
    ${PVC1_ROOT}/src/controller_b.cpp
    ${PVC1_ROOT}/src/finalization.cpp
    ${PVC1_ROOT}/src/key_schedule.cpp
    ${PVC1_ROOT}/src/return_pass.cpp)
target_include_directories(pvc_prf1_c1 PUBLIC ${PVC1_ROOT}/include)
target_compile_features(pvc_prf1_c1 PUBLIC cxx_std_20)
pvcmac0_apply_warnings(pvc_prf1_c1)

add_library(pvc_mac0 STATIC src/mac.cpp)
target_include_directories(pvc_mac0 PUBLIC include)
target_link_libraries(pvc_mac0 PUBLIC pvc_prf1_c1)
target_compile_features(pvc_mac0 PUBLIC cxx_std_20)
pvcmac0_apply_warnings(pvc_mac0)

add_library(pvc_mac0_independent STATIC independent/cpp_spec/src/mac.cpp)
target_include_directories(pvc_mac0_independent PUBLIC independent/cpp_spec/include)
target_link_libraries(pvc_mac0_independent PUBLIC pvc_prf1_c1)
target_compile_features(pvc_mac0_independent PUBLIC cxx_std_20)
pvcmac0_apply_warnings(pvc_mac0_independent)

add_executable(pvc-mac0 app/main.cpp)
target_link_libraries(pvc-mac0 PRIVATE pvc_mac0)
pvcmac0_apply_warnings(pvc-mac0)

if(PVCMAC0_BUILD_TOOLS)
    add_executable(pvc-mac0-vector-generator tools/vector_generator.cpp)
    target_link_libraries(pvc-mac0-vector-generator PRIVATE pvc_mac0)
    pvcmac0_apply_warnings(pvc-mac0-vector-generator)

    add_executable(pvc-mac0-framing-audit tools/framing_audit.cpp)
    target_link_libraries(pvc-mac0-framing-audit PRIVATE pvc_mac0)
    pvcmac0_apply_warnings(pvc-mac0-framing-audit)

    add_executable(pvc-mac0-avalanche-probe tools/avalanche_probe.cpp)
    target_link_libraries(pvc-mac0-avalanche-probe PRIVATE pvc_mac0)
    pvcmac0_apply_warnings(pvc-mac0-avalanche-probe)
endif()

if(PVCMAC0_BUILD_TESTS)
    enable_testing()
    add_executable(pvc-mac0-vector-corpus-tests tests/vector_corpus.cpp)
    target_link_libraries(pvc-mac0-vector-corpus-tests PRIVATE pvc_mac0)
    pvcmac0_apply_warnings(pvc-mac0-vector-corpus-tests)
    add_test(NAME pvc-mac0-vector-corpus
             COMMAND pvc-mac0-vector-corpus-tests ${CMAKE_CURRENT_SOURCE_DIR}/vectors/PVC_MAC0_VECTORS_0.1.0.csv)

    add_executable(pvc-mac0-independent-vector-corpus-tests tests/independent_vector_corpus.cpp)
    target_link_libraries(pvc-mac0-independent-vector-corpus-tests PRIVATE pvc_mac0_independent)
    pvcmac0_apply_warnings(pvc-mac0-independent-vector-corpus-tests)
    add_test(NAME pvc-mac0-independent-vector-corpus
             COMMAND pvc-mac0-independent-vector-corpus-tests ${CMAKE_CURRENT_SOURCE_DIR}/vectors/PVC_MAC0_VECTORS_0.1.0.csv)

    add_executable(pvc-mac0-independent-differential tests/independent_differential.cpp)
    target_link_libraries(pvc-mac0-independent-differential PRIVATE pvc_mac0 pvc_mac0_independent)
    pvcmac0_apply_warnings(pvc-mac0-independent-differential)
    add_test(NAME pvc-mac0-independent-differential
             COMMAND pvc-mac0-independent-differential --count ${PVCMAC0_DIFFERENTIAL_CASES})

    add_executable(pvc-mac0-integration-misuse-audit tests/integration_misuse_audit.cpp)
    target_link_libraries(pvc-mac0-integration-misuse-audit PRIVATE pvc_mac0 pvc_mac0_independent)
    pvcmac0_apply_warnings(pvc-mac0-integration-misuse-audit)
    add_test(NAME pvc-mac0-integration-misuse-audit
             COMMAND pvc-mac0-integration-misuse-audit)

    add_executable(pvc-mac0-tests tests/test_main.cpp)
    target_link_libraries(pvc-mac0-tests PRIVATE pvc_mac0)
    pvcmac0_apply_warnings(pvc-mac0-tests)

    set(PVCMAC0_TEST_CASES
        upstream-prf-vector
        framing-empty-exact
        framing-binary-exact
        framing-injective
        vector-zero-empty-256
        vector-zero-abc-256
        vector-incremental-binary-128
        determinism
        message-binding
        message-length-binding
        key-binding
        context-binding
        tag-size-domain-binding
        verify-accept
        verify-reject-tag
        verify-reject-message
        invalid-tag-size
        verify-all-supported-lengths
        verify-invalid-length-matrix
        verify-cross-profile-prefix-reject
        binary-null-preservation)
    foreach(test_case IN LISTS PVCMAC0_TEST_CASES)
        add_test(NAME pvc-mac0-${test_case} COMMAND pvc-mac0-tests --case ${test_case})
    endforeach()

    if(PVCMAC0_BUILD_TOOLS)
        add_test(NAME pvc-mac0-framing-audit-smoke COMMAND pvc-mac0-framing-audit)
    endif()
endif()
