#!/bin/sh
# Build !NetStats and NetStats-<ver>.zip (RISC OS filetypes kept in the zip)
set -e
cd "$(dirname "$0")"
VER=1.05-rc2
rm -rf build && mkdir -p build/'!NetStats'
A=build/'!NetStats'
cp appsrc/'!Run,feb' appsrc/'!Boot,feb' appsrc/'!Help,fff' "$A/"
python3 tools/tokenise.py src/RunImage.bas "$A/!RunImage,ffb"
python3 tools/mksprites.py "$A/!Sprites,ff9"
mkdir -p build/preview && mv "$A"/'!Sprites,ff9'-*.png build/preview/ 2>/dev/null || true
(cd build && python3 ../tools/rozip.py NetStats-$VER.zip '!NetStats')
# source package
rm -f build/NetStats-$VER-src.zip
zip -qr build/NetStats-$VER-src.zip src appsrc tools tests/make_fixtures.py tests/test_main.bas tests/run_tests.sh tests/inetstat.txt tests/obsd make.sh README.md CHANGELOG.md LICENSE
ls -l build build/'!NetStats'
