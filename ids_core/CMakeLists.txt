cmake_minimum_required(VERSION 3.16)
project(ids_core LANGUAGES C)

add_library(ids_core STATIC
    src/capture.c
    src/packet_handler.c
    src/datalink.c
    src/network.c
    src/transport.c
    src/rules.c
    src/ml_bridge.c
    src/alerts.c
    src/ids_api.c
)

target_include_directories(ids_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# ---- Link libpcap + Windows sockets ----
target_link_libraries(ids_core
    ${PCAP_LIBRARIES}
    ws2_32
)