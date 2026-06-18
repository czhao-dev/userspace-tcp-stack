add_executable(chat_server chat_server.cpp)
target_link_libraries(chat_server PRIVATE minitcp_core)

add_executable(chat_client chat_client.cpp)
target_link_libraries(chat_client PRIVATE minitcp_core)
