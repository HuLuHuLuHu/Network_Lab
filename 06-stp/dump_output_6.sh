#!/bin/bash

for i in `seq 1 6`;
do
    echo "NODE b$i dumps:";
    if [ $i -eq 3 -o $i -eq 4 ]; then
        tail -7 six_b$i-output.txt;
    else
        tail -5 six_b$i-output.txt;   
    fi
    echo "";
done
