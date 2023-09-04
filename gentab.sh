#!/bin/sh

echo "struct instdef unprefixed_instructions[256] = {"
jq .unprefixed < opcodes.json | jq -rf gentab.jq | awk -f gentab.awk
echo "};"

echo "struct instdef cbprefixed_instructions[256] = {"
jq .cbprefixed < opcodes.json | jq -rf gentab.jq | awk -f gentab.awk
echo "};"
