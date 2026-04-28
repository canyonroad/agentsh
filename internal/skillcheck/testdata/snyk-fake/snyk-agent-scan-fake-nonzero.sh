#!/bin/sh
# Test double: emits valid JSON then exits non-zero (mimicking "findings present").
cat "$(dirname "$0")/sample-output.json"
exit 1
