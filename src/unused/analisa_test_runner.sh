#!/bin/bash

# Written by Claudio André <claudioandre.br@gmail.com>

OIFS=$IFS;
IFS=",";

john="../run/john"

list=`$john --list=formats | tr '\n' ' ' `
listArray=($list);

for ((i=0; i<${#listArray[@]}; ++i));
do
    echo "Item $i: ${listArray[$i]//[[:space:]]}";
    $john --test -format:${listArray[$i]//[[:space:]]} --max-run-time=10
done

IFS=$OIFS;
