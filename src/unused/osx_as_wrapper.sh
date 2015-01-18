#!/bin/sh
HAS_INPUT_FILE=0
ARGS=$@
while [ $# -ne 0 ]; do
        ARG=$1
        # Skip options
        if [ $ARG == "-arch" ] || [ $ARG == "-o" ]; then
                # Skip next token
                shift
                shift
                continue
        fi

        if [ `echo $ARG | head -c1` == "-" ]; then
                shift
                continue
        fi

        HAS_INPUT_FILE=1
        break
done

if [ $HAS_INPUT_FILE -eq 1 ]; then
        clang -c -x assembler $ARGS
else
        clang -c -x assembler $ARGS -
fi
