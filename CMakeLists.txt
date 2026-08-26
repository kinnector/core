cmake_minimum_required(VERSION 3.20)
project(kinnector-core CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Configure output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

enable_testing()



# Common source files
set(CORE_SOURCES
    src/ipc.cpp
    src/telemetry.cpp
    src/ffi.cpp
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(STATUS "Configuring for Linux target")
    list(APPEND CORE_SOURCES
        src/linux/ebpf_loader.cpp
        src/linux/fanotify.cpp
        src/linux/warden_helper.cpp
        src/linux/linux_ipc.cpp
    )
    add_compile_definitions(TARGET_OS_LINUX)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    message(STATUS "Configuring for Windows target")
    list(APPEND CORE_SOURCES
        src/windows/etw_consumer.cpp
        src/windows/driver_helper.cpp
        src/windows/clipboard_helper.cpp
        src/windows/windows_ipc.cpp
        src/windows/resource_identity.cpp
        src/windows/authenticode.cpp
        src/windows/process_integrity.cpp
    )
    add_compile_definitions(TARGET_OS_WINDOWS)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    message(STATUS "Configuring for macOS target")
    list(APPEND CORE_SOURCES
        src/macos/esf_client.cpp
        src/macos/openbsm_parser.cpp
        src/macos/macos_ipc.cpp
    )
    add_compile_definitions(TARGET_OS_MACOS)
else()
    message(FATAL_ERROR "Unsupported platform: ${CMAKE_SYSTEM_NAME}")
endif()

add_library(kinnector-core STATIC ${CORE_SOURCES})
set_target_properties(kinnector-core PROPERTIES POSITION_INDEPENDENT_CODE ON)
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    # On Windows, kinnector-core-shared's import library and this static
    # archive would otherwise both resolve to lib/kinnector-core.lib and
    # silently clobber each other in a full build (whichever target links
    # second wins) - executables linked against the static target after that
    # get the DLL's near-empty import stub instead, failing on any internal
    # C++ symbol that isn't __declspec(dllexport)'d. Give the static output a
    # distinct name; the CMake target name (what target_link_libraries uses)
    # is unaffected. Linux/macOS don't collide here (.a vs .so).
    set_target_properties(kinnector-core PROPERTIES OUTPUT_NAME kinnector-core-static)
endif()

add_library(kinnector-core-shared SHARED ${CORE_SOURCES})
set_target_properties(kinnector-core-shared PROPERTIES
    OUTPUT_NAME kinnector-core
    POSITION_INDEPENDENT_CODE ON
    # ffi.h gates KINNECTOR_API dllexport/dllimport on kinnector_core_EXPORTS
    # specifically. CMake only auto-defines <target>_EXPORTS from the actual
    # target name (kinnector_core_shared_EXPORTS here), which never matches -
    # so without this, the DLL build never actually dllexports anything and
    # every FFI function silently falls through to the dllimport branch.
    DEFINE_SYMBOL kinnector_core_EXPORTS
)

target_include_directories(kinnector-core PUBLIC include)
target_include_directories(kinnector-core-shared PUBLIC include)

# Target-specific properties and link libraries
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # Link dependencies for eBPF/LSM loading
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBBPF REQUIRED libbpf)
    target_link_libraries(kinnector-core PRIVATE ${LIBBPF_LIBRARIES} pthread)
    target_include_directories(kinnector-core PRIVATE ${LIBBPF_INCLUDE_DIRS})
    target_link_libraries(kinnector-core-shared PRIVATE ${LIBBPF_LIBRARIES} pthread)
    target_include_directories(kinnector-core-shared PRIVATE ${LIBBPF_INCLUDE_DIRS})
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    # Link libraries for Windows ETW, IPC, and Authenticode verification
    # (wintrust/crypt32: WinVerifyTrust/CertGetNameStringA in etw_consumer.cpp)
    target_link_libraries(kinnector-core PRIVATE advapi32 ole32 tdh wintrust crypt32)
    target_link_libraries(kinnector-core-shared PRIVATE advapi32 ole32 tdh wintrust crypt32)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    # Link frameworks for macOS
    target_link_libraries(kinnector-core PRIVATE
        "-framework EndpointSecurity"
        "-framework Foundation"
        "-framework Security"
    )
    target_link_libraries(kinnector-core-shared PRIVATE
        "-framework EndpointSecurity"
        "-framework Foundation"
        "-framework Security"
    )
endif()


# Generate vmlinux.h from BTF
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h
        COMMAND bpftool btf dump file /sys/kernel/btf/vmlinux format c > ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h
        VERBATIM
        COMMENT "Generating vmlinux.h from kernel BTF..."
    )

    # Compile eBPF program
    find_program(CLANG_BPF "clang")
    if(CLANG_BPF)
        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/kinnector.bpf.o
            COMMAND ${CLANG_BPF} -target bpf -g -O2 -c 
                    -I${CMAKE_CURRENT_BINARY_DIR} 
                    -I/usr/include 
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/linux/ebpf/kinnector.bpf.c 
                    -o ${CMAKE_CURRENT_BINARY_DIR}/kinnector.bpf.o
            DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/linux/ebpf/kinnector.bpf.c ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h
            COMMENT "Compiling eBPF program..."
        )
        add_custom_target(ebpf_target DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/kinnector.bpf.o)
        add_dependencies(kinnector-core ebpf_target)
        add_dependencies(kinnector-core-shared ebpf_target)
    endif()
    # Add test executables
    add_executable(kinnector-test-ipc src/linux/test_ipc.cpp)
    target_link_libraries(kinnector-test-ipc PRIVATE kinnector-core)
    add_test(NAME test_ipc COMMAND kinnector-test-ipc)

    add_executable(kinnector-test-lsm src/linux/test_lsm.cpp)
    target_link_libraries(kinnector-test-lsm PRIVATE kinnector-core)
    add_test(NAME test_lsm COMMAND kinnector-test-lsm)

    add_executable(kinnector-test-telemetry src/linux/test_telemetry.cpp)
    target_link_libraries(kinnector-test-telemetry PRIVATE kinnector-core)
    add_test(NAME test_telemetry COMMAND kinnector-test-telemetry)

    add_executable(kinnector-test-warden-helper src/linux/test_warden_helper.cpp)
    target_link_libraries(kinnector-test-warden-helper PRIVATE kinnector-core)
    add_test(NAME test_warden_helper COMMAND kinnector-test-warden-helper)

    add_executable(kinnector-test-fanotify src/linux/test_fanotify.cpp)
    target_link_libraries(kinnector-test-fanotify PRIVATE kinnector-core)
    add_test(NAME test_fanotify COMMAND kinnector-test-fanotify)

    add_executable(kinnector-test-ebpf-loader src/linux/test_ebpf_loader.cpp)
    target_link_libraries(kinnector-test-ebpf-loader PRIVATE kinnector-core)
    add_test(NAME test_ebpf_loader COMMAND kinnector-test-ebpf-loader)

    add_executable(kinnector-test-linux-ipc src/linux/test_linux_ipc.cpp)
    target_link_libraries(kinnector-test-linux-ipc PRIVATE kinnector-core)
    add_test(NAME test_linux_ipc COMMAND kinnector-test-linux-ipc)

    add_executable(kinnector-test-ffi src/linux/test_ffi.cpp)
    target_link_libraries(kinnector-test-ffi PRIVATE kinnector-core)
    add_test(NAME test_ffi COMMAND kinnector-test-ffi)

    add_executable(kinnector-test-warden-all src/linux/test_warden_all.cpp)
    target_link_libraries(kinnector-test-warden-all PRIVATE kinnector-core)
    add_test(NAME test_warden_all COMMAND kinnector-test-warden-all)

    # LINUX_COVERAGE_PLAN.md "Testing strategy" item 1: real syscall-level
    # deny assertions. The probe is deliberately not linked against
    # kinnector-core -- see enforcement_probe.cpp's header comment.
    add_executable(kinnector-enforcement-probe src/linux/test_helpers/enforcement_probe.cpp)

    add_executable(kinnector-test-enforcement-e2e src/linux/test_enforcement_e2e.cpp)
    target_link_libraries(kinnector-test-enforcement-e2e PRIVATE kinnector-core)
    add_dependencies(kinnector-test-enforcement-e2e kinnector-enforcement-probe)
    add_test(NAME test_enforcement_e2e COMMAND kinnector-test-enforcement-e2e)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    add_executable(kinnector-runner src/windows/runner.cpp)
    # Links against the shared target deliberately: ffi.h's KINNECTOR_API
    # resolves to __declspec(dllimport) for any consumer that isn't building
    # kinnector_core_EXPORTS itself, which only kinnector-core-shared's import
    # library can satisfy - linking the static kinnector-core target here
    # leaves __imp_* FFI symbols unresolved (see the DEFINE_SYMBOL comment
    # above kinnector-core-shared).
    target_link_libraries(kinnector-runner PRIVATE kinnector-core-shared)

    add_executable(kinnector-test-clipboard-helper src/windows/test_clipboard_helper.cpp)
    target_link_libraries(kinnector-test-clipboard-helper PRIVATE kinnector-core)
    add_test(NAME test_clipboard_helper COMMAND kinnector-test-clipboard-helper)

    add_executable(kinnector-test-process-lineage src/windows/test_process_lineage.cpp)
    target_link_libraries(kinnector-test-process-lineage PRIVATE kinnector-core)
    add_test(NAME test_process_lineage COMMAND kinnector-test-process-lineage)
    # Needs real Administrator elevation to start a Kernel-Process ETW trace;
    # the test detects this itself and exits 127 rather than silently passing
    # or silently mock-falling-back (see core/CLAUDE.md's warning about that
    # anti-pattern on Linux's test_lsm/test_enforcement_e2e).
    set_tests_properties(test_process_lineage PROPERTIES SKIP_RETURN_CODE 127)

    add_executable(kinnector-test-file-events src/windows/test_file_events.cpp)
    target_link_libraries(kinnector-test-file-events PRIVATE kinnector-core)
    add_test(NAME test_file_events COMMAND kinnector-test-file-events)
    # Same elevation requirement/skip-not-mock pattern as test_process_lineage.
    set_tests_properties(test_file_events PROPERTIES SKIP_RETURN_CODE 127)

    add_executable(kinnector-test-registry-events src/windows/test_registry_events.cpp)
    target_link_libraries(kinnector-test-registry-events PRIVATE kinnector-core)
    add_test(NAME test_registry_events COMMAND kinnector-test-registry-events)
    set_tests_properties(test_registry_events PROPERTIES SKIP_RETURN_CODE 127)

    add_executable(kinnector-test-network-events src/windows/test_network_events.cpp)
    target_link_libraries(kinnector-test-network-events PRIVATE kinnector-core ws2_32)
    add_test(NAME test_network_events COMMAND kinnector-test-network-events)
    set_tests_properties(test_network_events PROPERTIES SKIP_RETURN_CODE 127)

    add_executable(kinnector-test-taskscheduler-events src/windows/test_taskscheduler_events.cpp)
    target_link_libraries(kinnector-test-taskscheduler-events PRIVATE kinnector-core)
    add_test(NAME test_taskscheduler_events COMMAND kinnector-test-taskscheduler-events)
    set_tests_properties(test_taskscheduler_events PROPERTIES SKIP_RETURN_CODE 127)

    add_executable(kinnector-test-resource-identity src/windows/test_resource_identity.cpp)
    target_link_libraries(kinnector-test-resource-identity PRIVATE kinnector-core)
    add_test(NAME test_resource_identity COMMAND kinnector-test-resource-identity)
    # No elevation needed - CreateHardLinkW and GetFileInformationByHandle
    # both work from a plain user session, unlike the ETW-based tests above.

    add_executable(kinnector-test-process-integrity src/windows/test_process_integrity.cpp)
    target_link_libraries(kinnector-test-process-integrity PRIVATE kinnector-core)
    add_test(NAME test_process_integrity COMMAND kinnector-test-process-integrity)
    # No elevation needed - pure in-memory store, no real ETW/injection detection involved yet.

    add_executable(kinnector-test-dpapi-events src/windows/test_dpapi_events.cpp)
    target_link_libraries(kinnector-test-dpapi-events PRIVATE kinnector-core crypt32)
    add_test(NAME test_dpapi_events COMMAND kinnector-test-dpapi-events)
    # Same elevation requirement/skip-not-mock pattern as test_process_lineage.
    set_tests_properties(test_dpapi_events PROPERTIES SKIP_RETURN_CODE 127)
endif()


# Formatting target (clang-format)
find_program(CLANG_FORMAT "clang-format")
if(CLANG_FORMAT)
    file(GLOB_RECURSE ALL_CXX_FILES
        "include/*.h"
        "src/*.cpp"
    )
    add_custom_target(format
        COMMAND ${CLANG_FORMAT} -i -style=file ${ALL_CXX_FILES}
        COMMENT "Formatting codebase..."
    )
endif()
