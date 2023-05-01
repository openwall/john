#! /bin/bash

# Run me from src folder

# Fix OpenCL stuff
echo "=> sed -i 's,\"../run/opencl/opencl_device_info.h\",\"../run/opencl/opencl_device_info.h\",g' opencl/*.[c-h]"
sed -i 's,\"../run/opencl/opencl_device_info.h\",\"../../run/opencl/opencl_device_info.h\",g' opencl/*.[c-h]

# Fix top folder stuff
echo "=> sed -i 's,\"poly1305-donna/,\"../poly1305-donna/,g' plugins/*.[c-h]"
sed -i 's,\"poly1305-donna/,\"../poly1305-donna/,g' plugins/*.[c-h]
echo "=> sed -i 's,\"yescrypt/,\"../yescrypt/,g' plugins/*.[c-h]"
sed -i 's,\"yescrypt/,\"../yescrypt/,g' plugins/*.[c-h]
echo "=> sed -i 's,\"blowfish.c\",\"../blowfish.c\",g' plugins/*.[c-h]"
sed -i 's,\"blowfish.c\",\"../blowfish.c\",g' plugins/*.[c-h]
echo "=> sed -i 's,\"rar_common.c\",\"../rar_common.c\",g' plugins/*.[c-h]"
sed -i 's,\"rar_common.c\",\"../rar_common.c\",g' plugins/*.[c-h]

# Moved files
FILES=$(ls *.h formats/*.h modes/*.h opencl/*.h)
FOLDERS=". formats modes opencl plugins"

for f in ${FOLDERS}; do
    echo "Parsing all files in: $f"

    for i in ${FILES}; do
        BASENAME=$(basename $i)
        DIRNAME=$(dirname $i)
        # echo "Parsing file $i in folder $DIRNAME"

        # If the header is in the current folder there is nothing to do
        if [[ $f == $DIRNAME ]]; then
            echo "Nothing to do: parsing file $i in $DIRNAME folder"
        else
            if [[ $f == "." ]]; then
                FULLNAME="$i"
            else
                FULLNAME="../$i"
            fi
            echo "=> sed -i 's,\"$BASENAME\",\"$FULLNAME\",g' $f/*.[c-h]"
            sed -i "s,\"$BASENAME\",\"$FULLNAME\",g" $f/*.[c-h]
        fi
    done
done
echo

# Moved files
FOLDERS="formats modes opencl plugins"

for f in ${FOLDERS}; do
    echo "Parsing Makefile for $f"
    FILES=$(ls $f/*.h $f/*.c)

    for i in ${FILES}; do
        BASENAME=$(basename $i)
        DIRNAME=$(dirname $i)
        FULLNAME="$i"

        echo "=> sed -i 's,[[:space:]]$BASENAME, $FULLNAME,g' Makefile.in"
        sed -i "s,[[:space:]]$BASENAME, $FULLNAME,g" Makefile.in
    done
done
echo
echo Done