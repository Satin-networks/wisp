add_executable(wisp_tests
  main.cpp
  wisp_test.cpp
  keys_test.cpp
  config_test.cpp
  netlink_test.cpp
  ipc_test.cpp
  tunnel_test.cpp
  dns_test.cpp
)

target_link_libraries(wisp_tests PRIVATE wisp_core)

add_test(NAME wisp_tests COMMAND wisp_tests)
