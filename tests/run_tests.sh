#!/bin/sh
# Run the BASIC unit tests under Matrix Brandy (sbrandy), using the tokenised program
set -e
cd "$(dirname "$0")"
mkdir -p fx && python3 make_fixtures.py "$PWD/fx" >/dev/null
awk 'f||/^DEF /{f=1} f' ../src/RunImage.bas | sed -e 's/^DEF FNsysctl(/DEF FNsysctl_real(/' -e 's/^DEF FNvar(/DEF FNvar_real(/' > /tmp/lib.bas
cat test_main.bas /tmp/lib.bas > /tmp/test_all.bas
python3 ../tools/tokenise.py /tmp/test_all.bas /tmp/test_all >/dev/null
timeout 60 sbrandy -quit /tmp/test_all 2>&1 | grep -v '^heap.c'
