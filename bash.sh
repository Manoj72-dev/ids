#!/usr/bin/env bash
set -e   

PROJECT_ROOT=$(pwd)
BUILD_DIR="$PROJECT_ROOT/build"
QT_PATH="/c/Qt/6.6.1/mingw_64"   

echo "=== IDS Build Script ==="

if [ ! -d "$BUILD_DIR" ]; then
    mkdir build
fi

cd build

echo "Cleaning old build..."
rm -rf *

echo "Running CMake..."
cmake .. -G "MinGW Makefiles" -DCMAKE_PREFIX_PATH=$QT_PATH

echo "Building..."
mingw32-make -j4

echo "Running GUI..."
./qt_gui/ids_gui.exe