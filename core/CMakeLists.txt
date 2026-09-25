add_library(wisp_core STATIC
  src/types.cpp
  src/config.cpp
  src/keys.cpp
  src/netlink.cpp
  src/ipc.cpp
  src/tunnel.cpp
  src/dns.cpp
)

target_include_directories(wisp_core
  PUBLIC include
  PRIVATE src
)

target_link_libraries(wisp_core PUBLIC PkgConfig::SODIUM)

target_compile_definitions(wisp_core PUBLIC WISP_VERSION="${PROJECT_VERSION}")
