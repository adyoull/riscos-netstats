REM test harness: replaces the Wimp main program
DIM b% 1024, tmp% 256:PROCconstants:PROCalloc:PROCload_stats_table
stackname$="Internet 7.09 (test)":nfail%=0
PRINT "== unit"
PROCeq(FNnum(5*4294967296+1000),"21,474,837,480")
PROCeq(FNnum(999),"999"):PROCeq(FNnum(1234567),"1,234,567"):PROCeq(FNnum(0),"0")
PROCeq(FNbytes(1023),"1023 B"):PROCeq(FNbytes(1536),"1.5 KB"):PROCeq(FNbytes(5*1073741824),"5.0 GB")
PROCeq(FNbytes(250*1048576),"250 MB")
bits%=FALSE:PROCeq(FNrate(2048),"2.0 KB/s"):bits%=TRUE:PROCeq(FNrate(125000),"1.0 Mbit/s"):bits%=FALSE
PROCeq(STR$FNdelta(5,-5),"10"):PROCeq(STR$FNtdiff(&80000010,&7FFFFFF0),"32"):PROCeq(STR$FNtadd(&7FFFFFF0,100),"-2147483564"):PROCeq(STR$FNdelta(-1,1),"4294967294")
PROCeq(FNhostport("192.168.1.50.22"),"192.168.1.50:22"):PROCeq(FNhostport("*.*"),"*:*")
PROCeq(FNhostport("fe80::1%lo0.123"),"fe80::1%lo0:123")
DIM t% 64
FOR i%=0 TO 15:t%?i%=0:NEXT:t%?0=&20:t%?1=&01:t%?2=&0D:t%?3=&B8:t%?15=1
PROCeq(FNip6(t%,"en0"),"2001:db8::1")
FOR i%=0 TO 15:t%?i%=0:NEXT:t%?0=&FE:t%?1=&80:t%?3=2:t%?15=1
PROCeq(FNip6(t%,"en0"),"fe80::1%en0")
FOR i%=0 TO 15:t%?i%=0:NEXT
PROCeq(FNip6(t%,""),"::")
FOR i%=0 TO 15:t%?i%=i%:NEXT
PROCeq(FNip6(t%,""),"1:203:405:607:809:a0b:c0d:e0f")
PROCeq(STR$FNnice(700),"1024"):PROCeq(STR$FNnice(1500),"2048"):PROCeq(STR$FNnice(3*1048576),"5242880")
bits%=TRUE:PROCeq(STR$FNnice(100000),"1000000"):bits%=FALSE
PROCeq(STR$FNver_from_help("Internet 7.09 (23 Apr 2026)"),"709")
PROCeq(STR$FNver_from_help("Internet	5.68 (07 Aug 2024)"),"568")
n%=FNsplit("tcp   0  52  a.1   b.2   ESTABLISHED",cw$())
PROCeq(STR$n%+cw$(0)+cw$(2)+cw$(5),"6tcp52ESTABLISHED")

bits%=FALSE:PROCeq(FNshort(500)+FNshort(1536)+FNshort(3*1048576),"500B1.5K3.0M")
bits%=TRUE:PROCeq(FNshort(125000),"1.0Mb"):bits%=FALSE
PRINT "== ROD stack"
stack%=2:fx$="fx/rod_iflist":tcpfx$="fx/rod_tcp536"
PROCread_ifaces(1):PROCread_stats(1)
PROCeq(ifa4$(1),"192.168.1.50/24")
PROCeq(ifa6$(1),"fe80::ba27:ebff:fe01:aff%en0/64, 2001:db8::1/48")
PROCeq(ifa4$(0),"127.0.0.1/8")
PROCeq(ifmac$(0),"")
fx$="fx/rod_iflist2":PROCread_ifaces(2):PROCread_stats(2)
PROCtotals:PROCbuild_text
PROCeq(STR$ifn%,"2")
PROCeq(ifname$(0)+" "+ifname$(1),"lo0 en0")
PROCeq(ifmac$(1),"b8:27:eb:01:0a:ff")
PROCeq(STR$ifmtu%(1)+" "+STR$iflink%(1)+" "+STR$iftype%(1),"1500 6 6")
PROCeq(FNnum(ib(1)),"21,475,087,480")
PROCeq(STR$rin(1),"125000"):PROCeq(STR$rout(1),"25000")
PROCeq(STR$totin+" "+STR$totout,"125000 25000")
PROCeq(FNnum(st_val(tcp_sndbyte%)),"30,064,771,077")
PROCeq(FNnum(st_val(tcp_rcvbyte%)),"38,654,705,787")
PROCeq(STR$st_val(0)+" "+STR$st_val(1)+" "+STR$st_val(2),"11 22 33")
PROCeq(STR$st_val(20),"55"):PROCeq(STR$st_val(19),"66")
PROCeq(STR$st_val(21)+" "+STR$st_val(22),"1000 900"):PROCeq(STR$st_val(26)+" "+STR$st_val(28),"5000 4000")
PROCeq(tcplayout$,"")
PROCdump(WIF%):PROCdump(WPROT%)
PRINT "== ROD stack, 8-byte aligned tcpstat"
tcpfx$="fx/rod_tcp560":stfirst%=TRUE:PROCread_stats(1)
PROCeq(FNnum(st_val(tcp_rcvbyte%)),"38,654,705,787"):PROCeq(STR$st_val(20),"55"):PROCeq(STR$st_val(19),"66")
PROCeq(FNnum(st_val(13)),"4,096")
tcpfx$="fx/rod_tcp536":stfirst%=TRUE:PROCread_stats(1)
PROCeq(FNnum(st_val(13)),"4,096")

PRINT "== old stack"
stack%=1:ifn%=0:fx$="fx/old_iflist"
DIM lt% 512:x%=OPENIN("fx/old_tcp"):FOR i%=0 TO 255:lt%?i%=BGET#x%:NEXT:CLOSE#x%
leg_done%=TRUE:leg_tcp%=lt%:leg_udp%=0:leg_ip%=0:tcpok%=TRUE:udpok%=FALSE:ipok%=FALSE:stfirst%=TRUE
PROCread_ifaces(1):PROCread_stats(1)
PROCeq(STR$ifn%,"2"):PROCeq(ifa4$(0),"10.0.0.7/16"):PROCeq(ifname$(1),"lo0")
fx$="fx/old_iflist2":PROCread_ifaces(2):PROCread_stats(2)
PROCtotals:PROCbuild_text
PROCeq(STR$ifn%,"1"):PROCeq(ifname$(0),"eh0")
PROCeq(STR$ifmtu%(0),"1500"):PROCeq(STR$rin(0)+" "+STR$rout(0),"256 1024")
PROCeq(STR$st_val(tcp_sndbyte%)+" "+STR$st_val(tcp_rcvbyte%),"100000 200000")
PROCeq(STR$st_ok%(20),"0")
PROCdump(WIF%):PROCdump(WPROT%)

PRINT "== interface list unavailable -> TCP fallback"
stack%=2:fx$="":tcpfx$="fx/rod_tcp536":stfirst%=TRUE:PROCread_ifaces(1):PROCread_stats(1):PROCtotals
PROCeq(STR$ifok%,"0"):PROCeq(srcnote$,"TCP data only (interface list unavailable)")
PROCeq(FNnum(sumob),"30,064,771,077")

PRINT "== routes (ROD)"
stack%=2:fx$="fx/rod_iflist":PROCread_ifaces(1):rtfx$="fx/rod_routes":rtn%=0:PROCread_routes
PROCeq(STR$rtn%,"6")
PROCeq(FNshowtabs(rt$(0)),"default |  | 192.168.1.1 | UGS | en0")
PROCeq(FNshowtabs(rt$(1)),"192.168.1.0/24 |  | direct (en0) | U | en0")
PROCeq(FNshowtabs(rt$(2)),"127.0.0.1 |  | 127.0.0.1 | UH | lo0")
PROCeq(gw4$,"192.168.1.1 (en0)"):PROCeq(gw6$,"fe80::1 (en0)")
PROCeq(FNshowtabs(rt$(4)),"2001:db8:1234:5678::/64")
PROCeq(FNshowtabs(rt$(5))," |  | direct (en0) | U | en0")
PROCtext_net:PROCdump(WNET%)
PRINT "== routes (old stack)"
stack%=1:ifn%=0:fx$="fx/old_iflist":PROCread_ifaces(1):rtfx$="fx/old_routes":rtn%=0:PROCread_routes
PROCeq(STR$rtn%,"2"):PROCeq(gw4$,"10.0.0.1 (eh0)"):PROCeq(FNshowtabs(rt$(1)),"10.0.0.0/16 |  | direct (eh0) | U | eh0")
PRINT "== usage"
PROCeq(FNdate_of("Sun,04 Oct 2026.12:34:56"),"2026-10-04"):PROCeq(FNdate_of("Mon,05 Jan 2026.00:00:01"),"2026-01-05")
PROCeq(FNplain(21474837480),"21474837480")
un%=0:PROCusage_day("2026-08-31",100,10):PROCusage_day("2026-09-01",1000,100):PROCusage_day("2026-09-01",24,4):PROCusage_day("2026-09-02",2048,0)
PROCeq(STR$un%+" "+STR$udin(1)+" "+STR$udout(1),"3 1024 104")
sessin=3072:sessout=1024:sessstart$="12:00 04 Oct":PROCtext_usage:PROCdump(WUSE%)
PROCeq(FNshowtabs(L$(WUSE%,3)),"This session | 3.0 KB | 1.0 KB | 4.0 KB"):PROCeq(L$(WUSE%,1),"~This session started 12:00 04 Oct (Reset session totals is on the menu).")
f%=FALSE:FOR i%=0 TO nlines%(WUSE%)-1:IF FNshowtabs(L$(WUSE%,i%))="2026-09 | 3.0 KB | 104 B | 3.1 KB" THEN f%=TRUE
NEXT:PROCeq(STR$f%,"-1")
PRINT "== interface choice"
stack%=2:ifn%=0:fx$="fx/rod_iflist":PROCread_ifaces(1):fx$="fx/rod_iflist2":PROCread_ifaces(2)
selif$="":loopback%=FALSE:PROCtotals:PROCeq(STR$totin,"125000")
selif$="lo0":PROCtotals:PROCeq(STR$totin,"0"):PROCeq(srcnote$,"")
selif$="wl0":PROCtotals:PROCeq(srcnote$,"wl0 is not present")
selif$="en0":PROCtotals:PROCeq(STR$totin+" "+STR$totout,"125000 25000")
selif$=""
PRINT "== empty list"
stack%=2:ifn%=0:PROCparse_iflist(ifbuf%,0):PROCeq(STR$ifn%,"0"):PROCtotals:PROCeq(STR$totin,"0")
PRINT "== connections"
crn%=0:x%=OPENIN("inetstat.txt"):WHILE NOT EOF#x%:cr$(crn%)=GET$#x%:crn%+=1:ENDWHILE:CLOSE#x%
nlines%(WCONN%)=0:PROCparse_conn("inetstat -an")
PROCdump(WCONN%)
PROCeq(L$(WCONN%,0),"~4 TCP (2 established, 2 listening), 1 UDP.  Click to refresh.")
PRINT "failures: ";nfail%
END

DEF PROCeq(a$,b$)
IF a$<>b$ THEN PRINT "FAIL: got [";a$;"] want [";b$;"]":nfail%+=1 ELSE PRINT "ok   ";b$
ENDPROC

DEF PROCdump(w%)
LOCAL i%
FOR i%=0 TO nlines%(w%)-1:PRINT "  | ";FNshowtabs(L$(w%,i%)):NEXT
ENDPROC

DEF FNshowtabs(s$)
LOCAL i%
i%=INSTR(s$,CHR$9)
WHILE i%:s$=LEFT$(s$,i%-1)+" | "+MID$(s$,i%+1):i%=INSTR(s$,CHR$9):ENDWHILE
=s$

REM mock: fixtures instead of the stack
DEF FNsysctl(m%, n%, buf%, size%)
LOCAL f$, x%, l%
IF m%!4=17 THEN f$=fx$
IF m%!4=17 AND m%!16=1 THEN f$=rtfx$
IF m%!4=2 AND m%!8=6 THEN f$=tcpfx$
IF m%!4=2 AND m%!8=17 THEN f$="fx/rod_udp"
IF m%!4=2 AND m%!8=0 THEN f$="fx/rod_ip"
IF f$="" THEN sysctl_err$="mock: no fixture":=-1
x%=OPENIN(f$):l%=EXT#x%
FOR i%=0 TO l%-1:buf%?i%=BGET#x%:NEXT
CLOSE#x%
=l%

REM mock: system variables
DEF FNvar(n$)
IF n$="Inet$HostName" THEN ="pi4"
IF n$="Inet$Resolvers" THEN ="192.168.1.1 1.1.1.1"
=""
