cmake_minimum_required(VERSION 3.16)
project(TRY_IDS)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# ---- libpcap ----
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(${PCAP_INCLUDE_DIRS})
link_directories(${PCAP_LIBRARY_DIRS})

# ---- Subprojects ----
add_subdirectory(ids_core)
add_subdirectory(qt_gui)