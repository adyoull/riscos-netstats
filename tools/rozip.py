#!/usr/bin/env python3
"""Zip a directory tree for RISC OS, keeping filetypes.

   rozip.py <out.zip> <dir> [<dir> ...]   (run from the directory's parent)

A file named "name,xxx" is stored as "name" with filetype &xxx, using the
InfoZip RISC OS extra field ("AC" / ARC0: load and exec address and
attributes), which SparkFS and InfoZip's RISC OS unzip both restore.
Files without a ,xxx suffix get &FFD (Data).
(Copied from the riscos-warzone2100 tools.)
"""
import os, re, struct, sys, time, zipfile

EXT_TYPES = {'.conf': 0xFFF, '.txt': 0xFFF, '.html': 0xFAF, '.png': 0xB60}

def riscos_extra(filetype, mtime):
    # Centiseconds since 1900-01-01, the RISC OS time format.
    cs = int((mtime + 2208988800) * 100)
    load = 0xFFF00000 | (filetype << 8) | ((cs >> 32) & 0xFF)
    exe = cs & 0xFFFFFFFF
    attr = 0x33                      # owner and public read/write
    data = b'ARC0' + struct.pack('<4I', load, exe, attr, 0)
    return struct.pack('<2H', 0x4341, len(data)) + data

def add(zf, path):
    base = os.path.basename(path)
    m = re.match(r'^(.*),([0-9a-fA-F]{3})$', base)
    if m:
        name = os.path.join(os.path.dirname(path), m.group(1))
        ftype = int(m.group(2), 16)
    else:
        name = path
        ftype = EXT_TYPES.get(os.path.splitext(base)[1].lower(), 0xFFD)
    mtime = os.path.getmtime(path)
    zi = zipfile.ZipInfo(name.replace(os.sep, '/'), time.localtime(mtime)[:6])
    zi.compress_type = zipfile.ZIP_DEFLATED
    zi.external_attr = 0o644 << 16
    zi.extra = riscos_extra(ftype, mtime)
    with open(path, 'rb') as f:
        zf.writestr(zi, f.read(), compresslevel=9)

def main():
    out = sys.argv[1]
    with zipfile.ZipFile(out, 'w') as zf:
        for top in sys.argv[2:]:
            for root, dirs, files in os.walk(top):
                dirs.sort()
                zi = zipfile.ZipInfo(root.replace(os.sep, '/') + '/')
                zi.external_attr = (0o40755 << 16) | 0x10
                zf.writestr(zi, b'')
                for f in sorted(x for x in files if not x.startswith(".")):
                    add(zf, os.path.join(root, f))

if __name__ == '__main__':
    main()
