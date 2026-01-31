cmake_minimum_required(VERSION 3.16)
project(ids_gui)

set(CMAKE_CXX_STANDARD 17)

# VERY IMPORTANT FOR QT 6
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)

add_executable(ids_gui
    main.cpp
    ids_wrapper.cpp
    MainWindow.cpp
    MainWindow.ui
)

target_include_directories(ids_gui PRIVATE
    ../ids_core/include
)

target_link_libraries(ids_gui PRIVATE
    Qt6::Widgets
    ids_core
)
