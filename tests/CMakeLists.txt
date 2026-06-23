add_executable(checksum_test checksum_test.cpp)
target_link_libraries(checksum_test PRIVATE minitcp_core)
add_test(NAME checksum_test COMMAND checksum_test)

add_executable(tcp_state_test tcp_state_test.cpp)
target_link_libraries(tcp_state_test PRIVATE minitcp_core)
add_test(NAME tcp_state_test COMMAND tcp_state_test)

add_executable(retransmission_test retransmission_test.cpp)
target_link_libraries(retransmission_test PRIVATE minitcp_core)
add_test(NAME retransmission_test COMMAND retransmission_test)

add_executable(udp_socket_test udp_socket_test.cpp)
target_link_libraries(udp_socket_test PRIVATE minitcp_core)
add_test(NAME udp_socket_test COMMAND udp_socket_test)

add_executable(sockopt_test sockopt_test.cpp)
target_link_libraries(sockopt_test PRIVATE minitcp_core)
add_test(NAME sockopt_test COMMAND sockopt_test)
