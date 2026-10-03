import re,sys
def body(path,name):
    t=open(path).read()
    m=re.search(r'struct\s+'+name+r'\s*\{(.*?)\n\};',t,re.S); return m.group(1)
SZ={'u_int32_t':4,'u_int64_t':8,'u_long':4,'u_int':4,'int':4}
def layout(b,a64):
    off=0;out=[]
    b=re.sub(r'/\*.*?\*/','',b,flags=re.S)
    for line in b.split(';'):
        line=line.strip()
        if not line or line.startswith('#'): continue
        m=re.match(r'(\w+)\s+(\w+)(?:\[(\w+)\s*(?:\+\s*1)?\])?$',line.split('\n')[-1].strip())
        if not m: print('??',repr(line),file=sys.stderr); continue
        ty,nm,arr=m.groups(); s=SZ[ty]; al=a64 if s==8 else 4
        off=(off+al-1)//al*al; n=1
        if arr: n={'ICMP_MAXTYPE':19}.get(arr,None) or int(arr); 
        out.append((nm,off,ty)); off+=s*n
    al=a64; off=(off+al-1)//al*al
    return out,off
for f,n in [('sys/netinet/tcp_var.h','tcpstat'),('sys/netinet/udp_var.h','udpstat'),('sys/netinet/ip_var.h','ipstat'),('sys/netinet/icmp_var.h','icmpstat')]:
    b=body(f,n)
    for a in (4,8):
        o,s=layout(b,a); print(n,'align',a,'size',s)
        if len(sys.argv)>1: [print('  ',x) for x in o]
