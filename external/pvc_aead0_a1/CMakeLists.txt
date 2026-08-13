cmake_minimum_required(VERSION 3.20)
project(perfectvaluecubeaead VERSION 0.2.0 LANGUAGES CXX)

option(PVCAEAD0_BUILD_TESTS "Build PVC-AEAD-0 tests" ON)
option(PVCAEAD0_BUILD_TOOLS "Build PVC-AEAD-0 research tools" ON)
set(PVCAEAD0_DIFFERENTIAL_CASES "4096" CACHE STRING "Differential cases used by CTest")

function(pvcaead0_apply_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive-)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
    endif()
endfunction()

set(M1_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/external/pvc_mac0_m1)
set(C1_ROOT ${M1_ROOT}/external/pvc_prf1_c1)

add_library(pvc_prf1_c1 STATIC
    ${C1_ROOT}/src/cube.cpp
    ${C1_ROOT}/src/controller.cpp
    ${C1_ROOT}/src/controller_b.cpp
    ${C1_ROOT}/src/finalization.cpp
    ${C1_ROOT}/src/key_schedule.cpp
    ${C1_ROOT}/src/return_pass.cpp)
target_include_directories(pvc_prf1_c1 PUBLIC ${C1_ROOT}/include)
target_compile_features(pvc_prf1_c1 PUBLIC cxx_std_20)
pvcaead0_apply_warnings(pvc_prf1_c1)

add_library(pvc_mac0_m1 STATIC ${M1_ROOT}/src/mac.cpp)
target_include_directories(pvc_mac0_m1 PUBLIC ${M1_ROOT}/include)
target_link_libraries(pvc_mac0_m1 PUBLIC pvc_prf1_c1)
target_compile_features(pvc_mac0_m1 PUBLIC cxx_std_20)
pvcaead0_apply_warnings(pvc_mac0_m1)

add_library(pvc_mac0_m1_independent STATIC ${M1_ROOT}/independent/cpp_spec/src/mac.cpp)
target_include_directories(pvc_mac0_m1_independent PUBLIC ${M1_ROOT}/independent/cpp_spec/include)
target_link_libraries(pvc_mac0_m1_independent PUBLIC pvc_prf1_c1)
target_compile_features(pvc_mac0_m1_independent PUBLIC cxx_std_20)
pvcaead0_apply_warnings(pvc_mac0_m1_independent)

add_library(pvc_aead0 STATIC src/aead.cpp)
target_include_directories(pvc_aead0 PUBLIC include)
target_link_libraries(pvc_aead0 PUBLIC pvc_mac0_m1 pvc_prf1_c1)
target_compile_features(pvc_aead0 PUBLIC cxx_std_20)
pvcaead0_apply_warnings(pvc_aead0)

add_library(pvc_aead0_independent STATIC independent/cpp_spec/src/aead.cpp)
target_include_directories(pvc_aead0_independent PUBLIC independent/cpp_spec/include)
target_link_libraries(pvc_aead0_independent PUBLIC pvc_mac0_m1_independent pvc_prf1_c1)
target_compile_features(pvc_aead0_independent PUBLIC cxx_std_20)
pvcaead0_apply_warnings(pvc_aead0_independent)

add_executable(pvc-aead0 app/main.cpp)
target_link_libraries(pvc-aead0 PRIVATE pvc_aead0)
pvcaead0_apply_warnings(pvc-aead0)

if(PVCAEAD0_BUILD_TOOLS)
    add_executable(pvc-aead0-vector-generator tools/vector_generator.cpp)
    target_link_libraries(pvc-aead0-vector-generator PRIVATE pvc_aead0)
    pvcaead0_apply_warnings(pvc-aead0-vector-generator)

    add_executable(pvc-aead0-nonce-reuse-demo tools/nonce_reuse_demo.cpp)
    target_link_libraries(pvc-aead0-nonce-reuse-demo PRIVATE pvc_aead0)
    pvcaead0_apply_warnings(pvc-aead0-nonce-reuse-demo)

    add_executable(pvc-aead0-framing-audit tools/framing_audit.cpp)
    target_link_libraries(pvc-aead0-framing-audit PRIVATE pvc_aead0)
    pvcaead0_apply_warnings(pvc-aead0-framing-audit)

    add_executable(pvc-aead0-composition-audit tools/composition_audit.cpp)
    target_link_libraries(pvc-aead0-composition-audit PRIVATE pvc_aead0)
    pvcaead0_apply_warnings(pvc-aead0-composition-audit)
endif()

if(PVCAEAD0_BUILD_TESTS)
    enable_testing()
    add_executable(pvc-aead0-vector-corpus-tests tests/vector_corpus.cpp)
    target_link_libraries(pvc-aead0-vector-corpus-tests PRIVATE pvc_aead0)
    pvcaead0_apply_warnings(pvc-aead0-vector-corpus-tests)
    add_test(NAME pvc-aead0-vector-corpus
             COMMAND pvc-aead0-vector-corpus-tests ${CMAKE_CURRENT_SOURCE_DIR}/vectors/PVC_AEAD0_VECTORS_0.1.0.csv)

    add_executable(pvc-aead0-independent-vector-corpus-tests tests/independent_vector_corpus.cpp)
    target_link_libraries(pvc-aead0-independent-vector-corpus-tests PRIVATE pvc_aead0_independent)
    pvcaead0_apply_warnings(pvc-aead0-independent-vector-corpus-tests)
    add_test(NAME pvc-aead0-independent-vector-corpus
             COMMAND pvc-aead0-independent-vector-corpus-tests ${CMAKE_CURRENT_SOURCE_DIR}/vectors/PVC_AEAD0_VECTORS_0.1.0.csv)

    add_executable(pvc-aead0-independent-differential tests/independent_differential.cpp)
    target_link_libraries(pvc-aead0-independent-differential PRIVATE pvc_aead0 pvc_aead0_independent pvc_prf1_c1)
    pvcaead0_apply_warnings(pvc-aead0-independent-differential)
    add_test(NAME pvc-aead0-independent-differential
             COMMAND pvc-aead0-independent-differential --count ${PVCAEAD0_DIFFERENTIAL_CASES})

    add_executable(pvc-aead0-tests tests/test_main.cpp)
    target_link_libraries(pvc-aead0-tests PRIVATE pvc_aead0)
    pvcaead0_apply_warnings(pvc-aead0-tests)

    set(PVCAEAD0_TEST_CASES
        stream-frame-exact
        auth-frame-exact
        independent-key-canonical-vector
        stream-counter-boundaries
        frame-family-domain-separation
        auth-frame-injectivity-witnesses
        empty-roundtrip
        binary-roundtrip
        multiblock-roundtrip
        determinism
        nonce-binding
        encryption-key-binding
        authentication-key-binding
        associated-data-binding
        ciphertext-binding
        tag-binding
        tag-size-domain-binding
        wrong-nonce-reject
        wrong-ad-reject
        wrong-ciphertext-reject
        wrong-tag-reject
        invalid-tag-length-reject
        cross-profile-prefix-reject
        verify-before-decrypt
        nonce-reuse-xor-demonstration
        zero-length-ciphertext-authentication)
    foreach(test_case IN LISTS PVCAEAD0_TEST_CASES)
        add_test(NAME pvc-aead0-${test_case} COMMAND pvc-aead0-tests --case ${test_case})
    endforeach()

    if(PVCAEAD0_BUILD_TOOLS)
        add_test(NAME pvc-aead0-framing-audit-smoke COMMAND pvc-aead0-framing-audit)
        add_test(NAME pvc-aead0-composition-audit-smoke COMMAND pvc-aead0-composition-audit)
    endif()
endif()
