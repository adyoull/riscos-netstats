#!/usr/bin/env python3
"""Build binary fixtures that mimic what the two stacks return from
Socket_Sysctl, using the struct layouts from the stack headers:
  ROD (OpenBSD 6.8 headers in johnballance/internet6): if_msghdr/if_data,
      ifa_msghdr, tcpstat (64-bit fields), udpstat, ipstat
  Old stack (ROOL TCPIPLibs, 4.4BSD/FreeBSD): if_msghdr/if_data, ifa_msghdr
"""
import struct, os, sys
sys.path.insert(0, os.path.dirname(__file__))
out = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else '.')

def roundup(n):
    return 4 if n == 0 else ((n - 1) | 3) + 1

def sa_pad(b):
    return b + b'\0' * (roundup(len(b)) - len(b))

def sdl(index, iftype, name, mac):
    data = name.encode() + mac
    body = struct.pack('<BBHBBBB', 0, 18, index, iftype, len(name), len(mac), 0) + data
    body = body + b'\0' * max(0, 8 + 24 - len(body))     # sdl_data[24] minimum
    body = bytes([len(body)]) + body[1:]
    return sa_pad(body)

def sin(addr, length=16):
    b = struct.pack('<BBH', length, 2, 0) + bytes(addr) + b'\0' * 8
    return sa_pad(b[:length])

def sin6(addr16, family=24, length=28):
    b = struct.pack('<BBHI', length, family, 0, 0) + bytes(addr16) + struct.pack('<I', 0)
    return sa_pad(b[:length])

def mask4(prefix):
    m = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    mb = m.to_bytes(4, 'big')
    # kernels trim trailing zero bytes from netmasks
    n = 4 + len(mb.rstrip(b'\0'))
    return sa_pad(bytes([n, 0, 0, 0]) + mb[:n - 4])

def mask6(prefix):
    m = ((1 << 128) - 1) ^ ((1 << (128 - prefix)) - 1)
    mb = m.to_bytes(16, 'big')
    n = 8 + len(mb.rstrip(b'\0'))
    return sa_pad(bytes([n, 0, 0, 0]) + b'\0' * 4 + mb[:n - 8])

# ---------------------------------------------------------------- ROD
def rod_ifinfo(index, flags, iftype, link, mtu, baud, c, sdlb):
    ifdata = struct.pack('<BBBBIII', iftype, 6, 14, link, mtu, 0, 0)
    ifdata += struct.pack('<Q', baud)
    for k in ('ipk', 'ierr', 'opk', 'oerr', 'coll', 'ib', 'ob', 'imc', 'omc', 'iqd', 'oqd', 'noproto'):
        ifdata += struct.pack('<Q', c.get(k, 0))
    ifdata += struct.pack('<I', 0) + struct.pack('<qI', 0, 0)  # caps, timeval
    hdrlen = 24 + len(ifdata)
    addrs = 0x10
    body = sdlb
    msglen = hdrlen + len(body)
    h = struct.pack('<HBBHHHBBiii', msglen, 5, 0xE, hdrlen, index, 0, 0, 0, addrs, flags, 0)
    assert len(h) == 24
    return h + ifdata + body

def rod_newaddr(index, mask, ifp, ifa):
    hdrlen = 24
    addrs = 0x4 | 0x10 | 0x20
    body = mask + ifp + ifa
    msglen = hdrlen + len(body)
    h = struct.pack('<HBBHHHBBiii', msglen, 5, 0xC, hdrlen, index, 0, 0, 0, addrs, 0, 0)
    return h + body

TWO32 = 1 << 32
en0 = dict(ipk=123456, ierr=2, opk=65432, oerr=1, ib=5 * TWO32 + 1000, ob=3000000, iqd=7, oqd=3)
lo0 = dict(ipk=10, opk=10, ib=640, ob=640)
mac = bytes([0xB8, 0x27, 0xEB, 0x01, 0x0A, 0xFF])
rod = b''
rod += rod_ifinfo(3, 0x8049, 24, 0, 32768, 0, lo0, sdl(3, 24, 'lo0', b''))
rod += rod_newaddr(3, mask4(8), sdl(3, 24, 'lo0', b''), sin([127, 0, 0, 1]))
rod += rod_ifinfo(1, 0x8843, 6, 6, 1500, 1000000000, en0, sdl(1, 6, 'en0', mac))
rod += rod_newaddr(1, mask4(24), sdl(1, 6, 'en0', mac), sin([192, 168, 1, 50]))
ll = [0xFE, 0x80, 0, 1] + [0] * 4 + [0xBA, 0x27, 0xEB, 0xFF, 0xFE, 0x01, 0x0A, 0xFF]
rod += rod_newaddr(1, mask6(64), sdl(1, 6, 'en0', mac), sin6(ll))
g6 = [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
rod += rod_newaddr(1, mask6(48), sdl(1, 6, 'en0', mac), sin6(g6))
open(os.path.join(out, 'rod_iflist'), 'wb').write(rod)

# second sample: en0 counters moved on; low word of ib wraps past 2^32
en0b = dict(en0)
en0b['ib'] = en0['ib'] + 250000
en0b['ob'] = en0['ob'] + 50000
rod2 = rod_ifinfo(3, 0x8049, 24, 0, 32768, 0, lo0, sdl(3, 24, 'lo0', b'')) + \
       rod_ifinfo(1, 0x8843, 6, 6, 1500, 1000000000, en0b, sdl(1, 6, 'en0', mac))
open(os.path.join(out, 'rod_iflist2'), 'wb').write(rod2)

# tcpstat, 4-byte aligned 64-bit fields (536 bytes) and 8-byte (560 bytes)
here = os.path.dirname(os.path.abspath(__file__))
obsd = os.path.join(here, 'obsd')            # OpenBSD tcp_var.h at the stack's import commit
src = open(os.path.join(obsd, 'layout.py')).read().split('for f,n in')[0]
os.chdir(obsd)
exec(src)
vals = {'tcps_connattempt': 11, 'tcps_accepts': 22, 'tcps_connects': 33, 'tcps_sndbyte': 7 * TWO32 + 5,
        'tcps_rcvbyte': 9 * TWO32 + 123, 'tcps_sndrexmitbyte': 4096, 'tcps_rcvtotal': 777,
        'tcps_noport': 55, 'tcps_rcvoopack': 66}
for al, size in ((4, 536), (8, 560)):
    lay, sz = layout(body('sys/netinet/tcp_var.h', 'tcpstat'), al)
    assert sz == size, sz
    b = bytearray(sz)
    for name, off, ty in lay:
        v = vals.get(name, 0)
        struct.pack_into('<Q' if ty == 'u_int64_t' else '<I', b, off, v)
    open(os.path.join(out, 'rod_tcp%d' % size), 'wb').write(bytes(b))
u = bytearray(52); struct.pack_into('<I', u, 0, 1000); struct.pack_into('<I', u, 44, 900)
open(os.path.join(out, 'rod_udp'), 'wb').write(bytes(u))
ip = bytearray(132); struct.pack_into('<I', ip, 0, 5000); struct.pack_into('<I', ip, 56, 4000)
open(os.path.join(out, 'rod_ip'), 'wb').write(bytes(ip))

# ---------------------------------------------------------------- old stack
def old_ifinfo(index, flags, iftype, mtu, c, sdlb):
    ifdata = struct.pack('<BBBBBBxx', iftype, 0, 6, 14, 0, 0)
    for k in ('mtu', 'metric', 'baud', 'ipk', 'ierr', 'opk', 'oerr', 'coll', 'ib', 'ob', 'imc', 'omc', 'iqd', 'noproto', 'rt', 'xt'):
        ifdata += struct.pack('<I', {'mtu': mtu}.get(k, c.get(k, 0)) & 0xFFFFFFFF)
    ifdata += struct.pack('<II', 0, 0)
    assert len(ifdata) == 80
    addrs = 0x10
    msglen = 16 + 80 + len(sdlb)
    h = struct.pack('<HBBiiHxx', msglen, 5, 0xE, addrs, flags, index)
    assert len(h) == 16
    return h + ifdata + sdlb

def old_newaddr(index, mask, ifp, ifa):
    addrs = 0x4 | 0x10 | 0x20
    body = mask + ifp + ifa
    h = struct.pack('<HBBiiHxxi', 20 + len(body), 5, 0xC, addrs, 0, index, 0)
    assert len(h) == 20
    return h + body

old = old_ifinfo(1, 0x863, 6, 1500, dict(ipk=500, opk=400, ib=0xFFFFFF00, ob=1234, iqd=9), sdl(1, 6, 'eh0', mac))
old += old_newaddr(1, mask4(16), sdl(1, 6, 'eh0', mac), sin([10, 0, 0, 7]))
old += old_ifinfo(2, 0x8049, 24, 16384, dict(ib=100, ob=100), sdl(2, 24, 'lo0', b''))
open(os.path.join(out, 'old_iflist'), 'wb').write(old)
old2 = old_ifinfo(1, 0x863, 6, 1500, dict(ipk=520, opk=410, ib=0x00000100, ob=1234 + 2048, iqd=9), sdl(1, 6, 'eh0', mac))
open(os.path.join(out, 'old_iflist2'), 'wb').write(old2)
# old tcpstat: u_long array; sndbyte index 17, rcvbyte 27
t = bytearray(4 * 64)
for i, v in ((0, 3), (1, 4), (17, 100000), (27, 200000), (25, 999)):
    struct.pack_into('<I', t, 4 * i, v)
open(os.path.join(out, 'old_tcp'), 'wb').write(bytes(t))
print('fixtures written to', out)
