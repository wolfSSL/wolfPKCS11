#!/bin/sh
# This script depends on g++, cmake, git, and make to be installed

POSIXLY_CORRECT=1

GEN_HTML=false
GEN_PDF=false
GEN_ALL=false
INSTALL_DOX=false

for var in "$@"
do
    case $var in
    -install)
        INSTALL_DOX=true
        ;;
    -html)
        GEN_HTML=true
        ;;
    -pdf)
        GEN_PDF=true
        ;;
    -all)
        GEN_ALL=true
        ;;
    esac
done

if [ $INSTALL_DOX = true ] && [ ! "$(which doxygen)" ]; then
    mkdir -p build
    cd build
    echo "cloning doxygen 1.8.13..."
    git clone --depth 1 --branch Release_1_8_13 https://github.com/doxygen/doxygen
    cmake -G "Unix Makefiles" doxygen/
    make
    cd ..
    export PATH="./build/bin/:$PATH"
fi

if [ $GEN_HTML = true ] || [ $GEN_ALL = true ]; then
    cp -r formats/html/* ./
    echo "generating html..."
    doxygen Doxyfile
    rm -f Doxyfile
    echo "finished generating html..."
    echo "Open doc/html/index.html to view."
fi

if [ $GEN_PDF = true ] || [ $GEN_ALL = true ]; then
    cp -r formats/pdf/* ./
    echo "generating pdf..."
    doxygen Doxyfile
    cd latex/ || exit 1
    make
    mv refman.pdf ../
    cd ..
    rm -rf latex/
    rm -f Doxyfile
    echo "finished generating pdf..."
fi
