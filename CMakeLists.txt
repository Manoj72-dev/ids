cmake_minimum_required(VERSION 3.16)
project(TRY_IDS)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# =========================
# Npcap SDK paths
# =========================
set(NPCAP_SDK "C:/npcap-sdk-1.16")

include_directories(
    ${NPCAP_SDK}/Include
)

link_directories(
    ${NPCAP_SDK}/Lib/x64
)

# =========================
# Subprojects
# =========================
add_subdirectory(ids_core)
add_subdirectory(qt_gui)
