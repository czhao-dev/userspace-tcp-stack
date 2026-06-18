add_executable(checksum_test checksum_test.cpp)
target_link_libraries(checksum_test PRIVATE minitcp_core)
add_test(NAME checksum_test COMMAND checksum_test)

# tcp_state_test and retransmission_test land in Phase 4/5 once tcp.cpp exists.
