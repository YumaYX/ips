#!/bin/bash

filename="${1}"

echo "${filename}"
/usr/local/bin/ys-ollama2file "${filename}"
cp -v output.txt "${filename}"

make || git checkout -f  "${filename}"
