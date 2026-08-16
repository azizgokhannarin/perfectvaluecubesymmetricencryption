cmake_minimum_required(VERSION 3.20)
project(perfectvaluecubesymmetricencryption VERSION 0.1.0 LANGUAGES CXX)

option(PVCROTSYMENC1_BUILD_TESTS "Build PVC-RotSymEnc-1 tests" ON)
option(PVCROTSYMENC1_BUILD_FUZZERS "Build Clang libFuzzer differential targets" OFF)
option(PVCROTSYMENC1_WARNINGS_AS_ERRORS "Treat warnings as errors" ON)
set(PVCROTSYMENC1_EQUIVALENCE_CASES "512" CACHE STRING "A1-equivalence cases used by CTest")
set(PVCROTSYMENC1_SANITIZER "none" CACHE STRING "Sanitizer profile: none, address, undefined, or memory")
set_property(CACHE PVCROTSYMENC1_SANITIZER PROPERTY STRINGS none address undefined memory)

function(pvcrotsymenc1_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive-)
        if(PVCROTSYMENC1_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE /WX)
        endif()
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
        if(PVCROTSYMENC1_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
    endif()
endfunction()

set(_pvcrotsymenc1_supported_sanitizers none address undefined memory)
list(FIND _pvcrotsymenc1_supported_sanitizers
     "${PVCROTSYMENC1_SANITIZER}"
     _pvcrotsymenc1_sanitizer_index)
if(_pvcrotsymenc1_sanitizer_index EQUAL -1)
    message(FATAL_ERROR
        "Unsupported PVCROTSYMENC1_SANITIZER='${PVCROTSYMENC1_SANITIZER}'. "
        "Expected one of: none, address, undefined, memory")
endif()

if(PVCROTSYMENC1_BUILD_FUZZERS AND NOT PVCROTSYMENC1_SANITIZER STREQUAL "none")
    message(FATAL_ERROR
        "PVCROTSYMENC1_SANITIZER must be 'none' when fuzzers are enabled; "
        "fuzzer targets use their fixed AddressSanitizer/UBSan profile")
endif()

if(NOT PVCROTSYMENC1_SANITIZER STREQUAL "none")
    if(MSVC OR NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        message(FATAL_ERROR
            "PVCROTSYMENC1_SANITIZER requires GCC or Clang")
    endif()
    if(PVCROTSYMENC1_SANITIZER STREQUAL "memory")
        set(_pvcrotsymenc1_msan_systems Linux FreeBSD NetBSD)
        if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang"
           OR NOT CMAKE_SYSTEM_NAME IN_LIST _pvcrotsymenc1_msan_systems)
            message(FATAL_ERROR
                "MemorySanitizer requires upstream Clang on Linux, FreeBSD, or NetBSD")
        endif()
    endif()

    add_compile_options(
        "-fsanitize=${PVCROTSYMENC1_SANITIZER}"
        -fno-omit-frame-pointer)
    add_link_options("-fsanitize=${PVCROTSYMENC1_SANITIZER}")
    if(PVCROTSYMENC1_SANITIZER STREQUAL "memory")
        add_compile_options(
            -fsanitize-memory-track-origins=2
            -fno-optimize-sibling-calls)
    endif()
endif()

if(PVCROTSYMENC1_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "PVC-RotSymEnc-1 fuzzers require Clang and libFuzzer")
    endif()
    add_compile_options(-fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=fuzzer-no-link,address,undefined)
endif()

set(PVCAEAD0_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(PVCAEAD0_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
add_subdirectory(external/pvc_aead0_a1 EXCLUDE_FROM_ALL)

add_library(pvc_rotsymenc1 STATIC src/symmetric_encryption.cpp)
target_include_directories(pvc_rotsymenc1 PUBLIC include)
target_link_libraries(pvc_rotsymenc1 PUBLIC pvc_aead0)
target_compile_features(pvc_rotsymenc1 PUBLIC cxx_std_20)
pvcrotsymenc1_warnings(pvc_rotsymenc1)

add_executable(pvc-rotsymenc1 app/main.cpp)
target_link_libraries(pvc-rotsymenc1 PRIVATE pvc_rotsymenc1)
pvcrotsymenc1_warnings(pvc-rotsymenc1)

if(PVCROTSYMENC1_BUILD_TESTS)
    enable_testing()
    add_executable(pvc-rotsymenc1-tests tests/test_main.cpp)
    target_link_libraries(pvc-rotsymenc1-tests PRIVATE pvc_rotsymenc1 pvc_aead0)
    pvcrotsymenc1_warnings(pvc-rotsymenc1-tests)
    foreach(case_name IN ITEMS canonical-vector roundtrip tamper-reject tag-profile-invalid a1-byte-equivalence)
        add_test(NAME pvc-rotsymenc1-${case_name} COMMAND pvc-rotsymenc1-tests --case ${case_name})
    endforeach()

    add_executable(pvc-rotsymenc1-equivalence tests/equivalence.cpp)
    target_link_libraries(pvc-rotsymenc1-equivalence PRIVATE pvc_rotsymenc1 pvc_aead0)
    pvcrotsymenc1_warnings(pvc-rotsymenc1-equivalence)
    add_test(NAME pvc-rotsymenc1-a1-equivalence-corpus
             COMMAND pvc-rotsymenc1-equivalence --count ${PVCROTSYMENC1_EQUIVALENCE_CASES})
endif()

if(PVCROTSYMENC1_BUILD_FUZZERS)
    function(pvcrotsymenc1_add_fuzzer target source seed_corpus)
        add_executable(${target} ${source})
        target_include_directories(${target} PRIVATE fuzz)
        target_link_libraries(${target} PRIVATE pvc_rotsymenc1 pvc_aead0_independent)
        target_link_options(${target} PRIVATE -fsanitize=fuzzer,address,undefined)
        pvcrotsymenc1_warnings(${target})

        if(PVCROTSYMENC1_BUILD_TESTS)
            set(output_corpus "${CMAKE_CURRENT_BINARY_DIR}/fuzz-corpus/${target}")
            set(artifact_directory "${CMAKE_CURRENT_BINARY_DIR}/fuzz-artifacts/${target}")
            file(MAKE_DIRECTORY "${output_corpus}")
            file(MAKE_DIRECTORY "${artifact_directory}")
            add_test(
                NAME ${target}-smoke
                COMMAND ${target}
                        -seed=1
                        -runs=256
                        -max_len=4096
                        -artifact_prefix=${artifact_directory}/
                        "${output_corpus}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/${seed_corpus}")
            set_tests_properties(${target}-smoke PROPERTIES LABELS fuzz TIMEOUT 180)
        endif()
    endfunction()

    pvcrotsymenc1_add_fuzzer(
        pvc-rotsymenc1-fuzz-seal-equivalence
        fuzz/seal_equivalence.cpp
        fuzz/corpus/seal-equivalence)
    pvcrotsymenc1_add_fuzzer(
        pvc-rotsymenc1-fuzz-open-equivalence
        fuzz/open_equivalence.cpp
        fuzz/corpus/open-equivalence)
endif()
