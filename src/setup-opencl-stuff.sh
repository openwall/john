#!/usr/bin/env bash
for kernel in `ls *.cl`
do 
    cat opencl-tweaks.h "$kernel" > ../run/"$kernel"
done
