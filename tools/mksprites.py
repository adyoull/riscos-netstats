#!/usr/bin/env python3
"""Draw the !netstats application sprites and write a RISC OS sprite file.

Two sprites, 32bpp (sprite type 6, 90x90 dpi) with a 1bpp mask:
  !netstats     34x34 pixels (68x68 OS units) - Filer and icon bar
  sm!netstats   17x17 pixels                  - small Filer icons
The picture: a dark rounded panel with a green "download" area graph and a
red "upload" line, i.e. what the monitor window shows.
Also writes a PNG preview next to the sprite file if Pillow is available.
"""
import struct, sys, math

def draw(n):
    s = n / 34.0
    W = H = n
    px = [[None] * W for _ in range(H)]            # None = transparent
    r = 5 * s
    for y in range(H):
        for x in range(W):
            # rounded rectangle panel 1..W-2
            x0, y0, x1, y1 = 1, 3 * s, W - 2, H - 2
            cx = min(max(x, x0 + r), x1 - r)
            cy = min(max(y, y0 + r), y1 - r)
            if (x - cx) ** 2 + (y - cy) ** 2 <= r * r and x0 <= x <= x1 and y0 <= y <= y1:
                edge = (x - cx) ** 2 + (y - cy) ** 2 > (r - 1.2) ** 2 or x in (x0, x1)
                px[y][x] = (40, 52, 70) if edge else (24, 30, 42)
    # graph: y measured from the top in this array
    base = H - 2 - 3 * s
    def dl(x):
        t = x / W
        return 0.30 + 0.32 * math.sin(t * 6.0 + 0.6) ** 2 + 0.18 * t
    def ul(x):
        t = x / W
        return 0.12 + 0.10 * math.sin(t * 9.0 + 1.3) ** 2
    top_area = 6 * s
    span = base - top_area
    for x in range(int(3 * s), int(W - 3 * s)):
        hgt = base - dl(x) * span
        for y in range(int(hgt), int(base) + 1):
            if px[y][x] is not None:
                px[y][x] = (60, 190, 90) if y > hgt + 1.0 else (150, 245, 160)
        uy = int(round(base - ul(x) * span - 2 * s))
        for yy in (uy, uy + (1 if n > 20 else 0)):
            if 0 <= yy < H and px[yy][x] is not None:
                px[yy][x] = (235, 70, 60)
    # grid dots
    for gy in (top_area + span * 0.25, top_area + span * 0.5):
        for x in range(int(4 * s), int(W - 3 * s), 3):
            y = int(gy)
            if px[y][x] == (24, 30, 42):
                px[y][x] = (60, 72, 92)
    return px

def sprite(name, px):
    H = len(px); W = len(px[0])
    img = bytearray()
    for y in range(H):                       # RISC OS rows: top first
        for x in range(W):
            p = px[y][x] or (0, 0, 0)
            img += struct.pack('<I', p[0] | (p[1] << 8) | (p[2] << 16))
    mwords = (W + 31) // 32
    mask = bytearray()
    for y in range(H):
        bits = 0
        for x in range(W):
            if px[y][x] is not None:
                bits |= 1 << x
        mask += bits.to_bytes(mwords * 4, 'little')
    mode = (6 << 27) | (90 << 14) | (90 << 1) | 1
    hdr = 44
    size = hdr + len(img) + len(mask)
    nm = name.encode().ljust(12, b'\0')
    h = struct.pack('<I', size) + nm + struct.pack('<7I', W - 1, H - 1, 0, 31, hdr, hdr + len(img), mode)
    return h + img + mask

def main(out):
    sprites = [sprite('!netstats', draw(34)), sprite('sm!netstats', draw(17))]
    body = b''.join(sprites)
    area = struct.pack('<3I', len(sprites), 16, 16 + len(body)) + body
    open(out, 'wb').write(area)
    try:
        from PIL import Image
        for nm, n in (('big', 34), ('small', 17)):
            px = draw(n)
            im = Image.new('RGBA', (n, n))
            for y in range(n):
                for x in range(n):
                    p = px[y][x]
                    im.putpixel((x, y), (p[0], p[1], p[2], 255) if p else (0, 0, 0, 0))
            im.resize((n * 8, n * 8), Image.NEAREST).save(out + '-%s.png' % nm)
    except ImportError:
        pass

if __name__ == '__main__':
    main(sys.argv[1])
