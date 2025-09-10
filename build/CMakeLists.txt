cmake_minimum_required(VERSION 3.12)
project(libhimitsu 
    VERSION 2.0.0 
    DESCRIPTION "Himitsu Protocol Core Library"
    HOMEPAGE_URL "https://github.com/hakaitech/libhimitsu"
    LANGUAGES C
)

# =============================================================================
# PROJECT CONFIGURATION
# =============================================================================
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Build options
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(BUILD_STATIC_LIBS "Build static libraries" ON)
option(BUILD_TESTS "Build test suite" ON)
option(BUILD_EXAMPLES "Build example programs" ON)
option(BUILD_BENCHMARKS "Build benchmark programs" OFF)
option(ENABLE_COVERAGE "Enable coverage reporting" OFF)
option(ENABLE_SANITIZERS "Enable sanitizers in debug builds" ON)
option(ENABLE_LTO "Enable link-time optimization" OFF)

# Installation options
option(INSTALL_HEADERS "Install header files" ON)
option(INSTALL_PKGCONFIG "Install pkg-config file" ON)

# =============================================================================
# BUILD TYPE CONFIGURATION
# =============================================================================
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic -Wstrict-prototypes -Wmissing-prototypes")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -DDEBUG")
    if(ENABLE_SANITIZERS)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fsanitize=undefined")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address -fsanitize=undefined")
    endif()
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -DNDEBUG")
    if(ENABLE_LTO)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
    endif()
endif()

if(ENABLE_COVERAGE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
endif()

# =============================================================================
# SOURCE CONFIGURATION
# =============================================================================
# Source files organized by component
set(CORE_SOURCES
    ../src/himitsu.c
    ../src/utils/error.c
    ../src/utils/memory.c
)

set(CRYPTO_SOURCES
    ../src/crypto/crypto.c
    ../src/crypto/ecdh.c
    ../src/crypto/sha256.c
    ../src/crypto/aes_gcm.c
)

set(PROTOCOL_SOURCES
    ../src/protocol/protocol.c
)

set(SERIALIZATION_SOURCES
    ../src/serialization/serialization.c
)

set(ALL_SOURCES
    ${CORE_SOURCES}
    ${CRYPTO_SOURCES}
    ${PROTOCOL_SOURCES}
    ${SERIALIZATION_SOURCES}
)

# Header files
file(GLOB_RECURSE PUBLIC_HEADERS "../include/himitsu/*.h")

# =============================================================================
# LIBRARY TARGETS
# =============================================================================
# Static library
if(BUILD_STATIC_LIBS)
    add_library(himitsu_static STATIC ${ALL_SOURCES})
    set_target_properties(himitsu_static PROPERTIES
        OUTPUT_NAME himitsu
        PUBLIC_HEADER "${PUBLIC_HEADERS}"
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
    target_include_directories(himitsu_static 
        PUBLIC 
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
            $<INSTALL_INTERFACE:include>
    )
    
    # Add alias for consistent naming
    add_library(libhimitsu::static ALIAS himitsu_static)
endif()

# Shared library
if(BUILD_SHARED_LIBS)
    add_library(himitsu_shared SHARED ${ALL_SOURCES})
    set_target_properties(himitsu_shared PROPERTIES
        OUTPUT_NAME himitsu
        PUBLIC_HEADER "${PUBLIC_HEADERS}"
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
    target_include_directories(himitsu_shared 
        PUBLIC 
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
            $<INSTALL_INTERFACE:include>
    )
    
    # Add alias for consistent naming
    add_library(libhimitsu::shared ALIAS himitsu_shared)
endif()

# Default library target
if(BUILD_SHARED_LIBS)
    add_library(libhimitsu::himitsu ALIAS himitsu_shared)
else()
    add_library(libhimitsu::himitsu ALIAS himitsu_static)
endif()

# Add custom targets for compatibility with Makefile interface
if(BUILD_STATIC_LIBS)
    add_custom_target(static DEPENDS himitsu_static)
endif()

if(BUILD_SHARED_LIBS)
    add_custom_target(shared DEPENDS himitsu_shared)
endif()

# =============================================================================
# TESTING
# =============================================================================
if(BUILD_TESTS)
    enable_testing()
    
    # Find test files
    file(GLOB UNIT_TEST_SOURCES "../tests/unit/*.c")
    file(GLOB INTEGRATION_TEST_SOURCES "../tests/integration/*.c")
    
    # Unit tests
    foreach(test_source ${UNIT_TEST_SOURCES})
        get_filename_component(test_name ${test_source} NAME_WE)
        add_executable(${test_name} ${test_source})
        target_link_libraries(${test_name} PRIVATE libhimitsu::himitsu)
        target_include_directories(${test_name} PRIVATE ../include)
        add_test(NAME ${test_name} COMMAND ${test_name})
        
        # Set test properties
        set_tests_properties(${test_name} PROPERTIES
            TIMEOUT 30
            LABELS "unit"
        )
    endforeach()
    
    # Integration tests
    foreach(test_source ${INTEGRATION_TEST_SOURCES})
        get_filename_component(test_name ${test_source} NAME_WE)
        add_executable(${test_name} ${test_source})
        target_link_libraries(${test_name} PRIVATE libhimitsu::himitsu)
        target_include_directories(${test_name} PRIVATE ../include)
        add_test(NAME ${test_name} COMMAND ${test_name})
        
        # Set test properties
        set_tests_properties(${test_name} PROPERTIES
            TIMEOUT 60
            LABELS "integration"
        )
    endforeach()
endif()

# =============================================================================
# EXAMPLES
# =============================================================================
if(BUILD_EXAMPLES)
    file(GLOB EXAMPLE_SOURCES "../examples/*.c")
    
    foreach(example_source ${EXAMPLE_SOURCES})
        get_filename_component(example_name ${example_source} NAME_WE)
        add_executable(example_${example_name} ${example_source})
        target_link_libraries(example_${example_name} PRIVATE libhimitsu::himitsu)
        target_include_directories(example_${example_name} PRIVATE ../include)
        
        # Set example properties
        set_target_properties(example_${example_name} PROPERTIES
            OUTPUT_NAME ${example_name}
            RUNTIME_OUTPUT_DIRECTORY examples
        )
    endforeach()
endif()

# =============================================================================
# BENCHMARKS
# =============================================================================
if(BUILD_BENCHMARKS)
    file(GLOB BENCHMARK_SOURCES "../benchmarks/*.c")
    
    foreach(benchmark_source ${BENCHMARK_SOURCES})
        get_filename_component(benchmark_name ${benchmark_source} NAME_WE)
        add_executable(benchmark_${benchmark_name} ${benchmark_source})
        target_link_libraries(benchmark_${benchmark_name} PRIVATE libhimitsu::himitsu)
        target_include_directories(benchmark_${benchmark_name} PRIVATE ../include)
        
        # Set benchmark properties
        set_target_properties(benchmark_${benchmark_name} PROPERTIES
            OUTPUT_NAME ${benchmark_name}
            RUNTIME_OUTPUT_DIRECTORY benchmarks
        )
    endforeach()
endif()

# =============================================================================
# INSTALLATION
# =============================================================================
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# Install targets
if(BUILD_STATIC_LIBS)
    install(TARGETS himitsu_static
        EXPORT libhimitsu-targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/himitsu
    )
endif()

if(BUILD_SHARED_LIBS)
    install(TARGETS himitsu_shared
        EXPORT libhimitsu-targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/himitsu
    )
endif()

# Install headers
if(INSTALL_HEADERS)
    install(DIRECTORY ../include/himitsu
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.h"
    )
endif()

# Create and install package config files
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/libhimitsu-config-version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    "libhimitsu-config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/libhimitsu-config.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libhimitsu
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/libhimitsu-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/libhimitsu-config-version.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libhimitsu
)

install(EXPORT libhimitsu-targets
    FILE libhimitsu-targets.cmake
    NAMESPACE libhimitsu::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libhimitsu
)

# Install pkg-config file
if(INSTALL_PKGCONFIG)
    configure_file(
        "libhimitsu.pc.in"
        "${CMAKE_CURRENT_BINARY_DIR}/libhimitsu.pc"
        @ONLY
    )
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libhimitsu.pc"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
    )
endif()

# =============================================================================
# CUSTOM TARGETS
# =============================================================================
# Code formatting
find_program(CLANG_FORMAT_EXECUTABLE clang-format)
if(CLANG_FORMAT_EXECUTABLE)
    add_custom_target(format
        COMMAND ${CLANG_FORMAT_EXECUTABLE} -i -style=file
            ${ALL_SOURCES} ${PUBLIC_HEADERS}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Formatting source code"
        VERBATIM
    )
endif()

# Static analysis
find_program(CPPCHECK_EXECUTABLE cppcheck)
if(CPPCHECK_EXECUTABLE)
    add_custom_target(analyze
        COMMAND ${CPPCHECK_EXECUTABLE}
            --enable=all --std=c99 --suppress=missingIncludeSystem
            --template='{file}:{line}: {severity}: {message}'
            ${CMAKE_CURRENT_SOURCE_DIR}/../src
        COMMENT "Running static analysis"
        VERBATIM
    )
endif()

# Coverage report
if(ENABLE_COVERAGE)
    find_program(LCOV_EXECUTABLE lcov)
    find_program(GENHTML_EXECUTABLE genhtml)
    
    if(LCOV_EXECUTABLE AND GENHTML_EXECUTABLE)
        add_custom_target(coverage
            COMMAND ${LCOV_EXECUTABLE} --capture --directory . --output-file coverage.info
            COMMAND ${GENHTML_EXECUTABLE} coverage.info --output-directory coverage-report
            DEPENDS ${UNIT_TEST_SOURCES} ${INTEGRATION_TEST_SOURCES}
            COMMENT "Generating coverage report"
            VERBATIM
        )
    endif()
endif()

# =============================================================================
# SUMMARY
# =============================================================================
message(STATUS "")
message(STATUS "=== libhimitsu Build Configuration ===")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C compiler: ${CMAKE_C_COMPILER}")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
message(STATUS "Build options:")
message(STATUS "  Shared libraries: ${BUILD_SHARED_LIBS}")
message(STATUS "  Static libraries: ${BUILD_STATIC_LIBS}")
message(STATUS "  Tests: ${BUILD_TESTS}")
message(STATUS "  Examples: ${BUILD_EXAMPLES}")
message(STATUS "  Benchmarks: ${BUILD_BENCHMARKS}")
message(STATUS "  Coverage: ${ENABLE_COVERAGE}")
message(STATUS "  Sanitizers: ${ENABLE_SANITIZERS}")
message(STATUS "  LTO: ${ENABLE_LTO}")
message(STATUS "")

# Find dependencies (to be added as development progresses)
# find_package(PkgConfig REQUIRED)
# pkg_check_modules(MBEDTLS mbedtls mbedcrypto mbedx509)

# Tests
if(BUILD_TESTS)
    enable_testing()
    
    # Find test files
    file(GLOB TEST_SOURCES "tests/*.c" "tests/*/*.c")
    
    foreach(TEST_SOURCE ${TEST_SOURCES})
        get_filename_component(TEST_NAME ${TEST_SOURCE} NAME_WE)
        add_executable(${TEST_NAME} ${TEST_SOURCE})
        
        if(BUILD_STATIC_LIBS)
            target_link_libraries(${TEST_NAME} himitsu_static)
        elseif(BUILD_SHARED_LIBS)
            target_link_libraries(${TEST_NAME} himitsu_shared)
        endif()
        
        add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
    endforeach()
endif()

# Examples
if(BUILD_EXAMPLES)
    file(GLOB EXAMPLE_SOURCES "examples/*.c")
    
    foreach(EXAMPLE_SOURCE ${EXAMPLE_SOURCES})
        get_filename_component(EXAMPLE_NAME ${EXAMPLE_SOURCE} NAME_WE)
        add_executable(${EXAMPLE_NAME} ${EXAMPLE_SOURCE})
        
        if(BUILD_STATIC_LIBS)
            target_link_libraries(${EXAMPLE_NAME} himitsu_static)
        elseif(BUILD_SHARED_LIBS)
            target_link_libraries(${EXAMPLE_NAME} himitsu_shared)
        endif()
    endforeach()
endif()

# Installation
include(GNUInstallDirs)

if(BUILD_STATIC_LIBS)
    install(TARGETS himitsu_static
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/himitsu
    )
endif()

if(BUILD_SHARED_LIBS)
    install(TARGETS himitsu_shared
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/himitsu
    )
endif()

# pkg-config file
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/libhimitsu.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/libhimitsu.pc"
    @ONLY
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libhimitsu.pc"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
)

# CPack configuration for packaging
set(CPACK_PACKAGE_NAME "libhimitsu")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "The Himitsu Protocol Core Library")
set(CPACK_PACKAGE_CONTACT "Himitsu Project")
set(CPACK_GENERATOR "TGZ;ZIP")

# Platform-specific settings
if(WIN32)
    set(CPACK_GENERATOR "${CPACK_GENERATOR};NSIS")
elseif(UNIX AND NOT APPLE)
    set(CPACK_GENERATOR "${CPACK_GENERATOR};DEB;RPM")
endif()

include(CPack)

# Custom targets
add_custom_target(format
    COMMAND find ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/tests ${CMAKE_SOURCE_DIR}/examples -name "*.c" -o -name "*.h" | xargs clang-format -i
    COMMENT "Formatting code"
)

add_custom_target(analyze
    COMMAND cppcheck --enable=all --std=c99 --suppress=missingIncludeSystem ${CMAKE_SOURCE_DIR}/src
    COMMENT "Running static analysis"
)
