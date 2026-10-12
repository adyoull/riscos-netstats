#!/usr/bin/env python3
"""Make NetStats's manufacturer table from the IEEE MA-L (OUI) registry.

  mkoui.py tsv <oui.txt> <data/oui.tsv>   IEEE oui.txt -> "XXXXXX<TAB>short name" (sorted)
  mkoui.py bin <data/oui.tsv> <OUI,ffd>   tsv -> the file !RunImage searches

oui.txt is the IEEE Registration Authority's public MA-L listing (the copy used
for data/oui.tsv came from the netaddr 1.3.0 Python package, which ships it
unchanged). Names are shortened to fit the Devices window.

Binary format: 16 byte header "NSOUI1\\0\\0", record count (4), record size (4),
then fixed records sorted by OUI: 3 bytes OUI (big-endian), 1 byte name length,
20 bytes name (ASCII, space padded).
"""
import re, struct, sys

NAMELEN = 20
SUFFIXES = [r',?\s+inc\.?$', r',?\s+co\.?,?\s*ltd\.?$', r',?\s+ltd\.?$', r',?\s+limited$',
            r',?\s+llc\.?$', r',?\s+gmbh$', r',?\s+corporation$', r',?\s+corp\.?$',
            r',?\s+ag$', r',?\s+s\.?a\.?$', r',?\s+b\.?v\.?$', r',?\s+co\.?$', r',?\s+plc$',
            r',?\s+s\.?r\.?l\.?$', r',?\s+s\.?p\.?a\.?$', r',?\s+pty$', r',?\s+oy$', r',?\s+ab$',
            r',?\s+a/s$', r',?\s+as$', r',?\s+kg$', r',?\s+&$', r'[,.\s]+$']

def short(name):
    s = re.sub(r'\s*\([^)]*\)', '', name).strip()
    s = s.encode('ascii', 'replace').decode().replace('?', '').strip()
    s = re.sub(r'\s+', ' ', s)
    for _ in range(4):
        for p in SUFFIXES:
            s = re.sub(p, '', s, flags=re.I).strip()
    if len(s) > NAMELEN:
        cut = s[:NAMELEN + 1].rsplit(' ', 1)[0] if ' ' in s[:NAMELEN + 1] else s[:NAMELEN]
        s = cut[:NAMELEN].rstrip(' ,.-&')
    return s or name[:NAMELEN]

def tsv(src, out):
    d = {}
    for line in open(src, encoding='utf-8', errors='replace'):
        m = re.match(r'^([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s+\(hex\)\s+(.*\S)', line)
        if m:
            d[m.group(1) + m.group(2) + m.group(3)] = short(m.group(4))
    with open(out, 'w') as f:
        for k in sorted(d):
            f.write('%s\t%s\n' % (k, d[k]))
    print(len(d), 'entries')

def binary(src, out):
    recs = []
    for line in open(src):
        k, n = line.rstrip('\n').split('\t')
        n = n.encode('ascii')[:NAMELEN]
        recs.append(bytes.fromhex(k) + bytes([len(n)]) + n.ljust(NAMELEN, b' '))
    recs.sort()
    with open(out, 'wb') as f:
        f.write(b'NSOUI1\0\0' + struct.pack('<2I', len(recs), 4 + NAMELEN))
        f.write(b''.join(recs))

if __name__ == '__main__':
    {'tsv': tsv, 'bin': binary}[sys.argv[1]](sys.argv[2], sys.argv[3])
