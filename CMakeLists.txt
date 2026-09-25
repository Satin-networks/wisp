cmake_minimum_required(VERSION 3.20)
project(wisp VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

# Sanitizers. Building with WISP_SANITIZE turns the test suite into a
# memory-error and undefined-behaviour hunt, which is the cheapest way to find
# real bugs before a human reviewer does.

option(WISP_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
if(WISP_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=all -g)
  add_link_options(-fsanitize=address,undefined)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
  message(STATUS "Sanitizers enabled (address, undefined)")
endif()

# Hardening. A program that holds private keys and reconfigures the network
# should not be built without these.

option(WISP_HARDEN "Enable compiler and linker hardening" ON)
if(WISP_HARDEN)
  # Stack canaries: catches the classic stack overwrite before it becomes a
  # control-flow hijack.
  add_compile_options(-fstack-protector-strong)

  # _FORTIFY_SOURCE replaces common libc calls with bounds-checked variants, but
  # it is a no-op without optimisation, so it is only worth defining above -O0.
  if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_definitions(_FORTIFY_SOURCE=2)
  endif()

  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
  add_compile_options(-fPIE)

  # Full RELRO plus immediate binding: the GOT cannot be rewritten after
  # startup, which removes a whole class of exploitation primitives.
  add_link_options(-Wl,-z,relro -Wl,-z,now -pie)
  message(STATUS "Hardening enabled (stack protector, fortify, RELRO, PIE)")
endif()

# Link-time optimisation. Helps the netlink encoder, which is called in tight
# loops during configuration.

option(WISP_LTO "Enable link-time optimisation" ON)
if(WISP_LTO AND NOT WISP_SANITIZE)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT wisp_lto_supported OUTPUT wisp_lto_error)
  if(wisp_lto_supported)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
    message(STATUS "Link-time optimisation enabled")
  else()
    message(STATUS "LTO unavailable: ${wisp_lto_error}")
  endif()
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

add_subdirectory(core)

option(WISP_BUILD_TESTS "Build the test suite" ON)
if(WISP_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

option(WISP_BUILD_HELPER "Build the privileged helper daemon" ON)
if(WISP_BUILD_HELPER)
  add_subdirectory(helper)
endif()

# The GUI needs Qt6. Looked for quietly so the core, helper and tests remain
# buildable on a machine without a Qt installation.
option(WISP_BUILD_APP "Build the Qt GUI" ON)
if(WISP_BUILD_APP)
  find_package(Qt6 QUIET COMPONENTS Core Gui Quick Qml)
  if(Qt6_FOUND)
    add_subdirectory(app)
  else()
    message(STATUS "Qt6 not found - building core, helper and tests only")
  endif()
endif()

# The benchmarks are a plain executable with no extra dependencies, so they are
# on by default: the cost of building them is trivial next to having a number to
# compare against when something feels slower than it used to.
option(WISP_BUILD_BENCH "Build the micro-benchmarks" ON)
if(WISP_BUILD_BENCH)
  add_subdirectory(bench)
endif()

option(WISP_BUILD_FUZZERS "Build libFuzzer targets (Clang only)" OFF)
if(WISP_BUILD_FUZZERS)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(WARNING "Fuzzers require Clang; none will be built")
  else()
    add_subdirectory(fuzz)
  endif()
endif()

# End-to-end test.
#
# The unit tests run against fakes because creating a real interface needs
# CAP_NET_ADMIN. This covers the half that can be checked without it: the
# helper's IPC surface driven over a real socket, and the GUI loading against a
# live helper. Registered only when everything it needs is present, so a build
# without Qt or socat still configures cleanly.

if(WISP_BUILD_TESTS AND WISP_BUILD_HELPER AND TARGET wispd AND TARGET wisp-app)
  find_program(SOCAT_EXECUTABLE socat)
  find_program(PYTHON3_EXECUTABLE python3)
  if(SOCAT_EXECUTABLE AND PYTHON3_EXECUTABLE)
    add_test(NAME wisp_integration
             COMMAND ${CMAKE_SOURCE_DIR}/scripts/integration-test.sh)
    set_tests_properties(wisp_integration PROPERTIES
      ENVIRONMENT "WISP_BUILD_DIR=${CMAKE_BINARY_DIR}" TIMEOUT 120)
  else()
    message(STATUS "socat or python3 not found - the integration test will not be registered")
  endif()
endif()

message(STATUS "wisp ${PROJECT_VERSION} configured (build type: ${CMAKE_BUILD_TYPE})")
