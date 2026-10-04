REM >!RunImage
REM NetStats - network statistics for RISC OS
REM Works with the RISC OS Developments (ROD) TCP/IP stack (Internet 7.x,
REM OpenBSD based) and with the older Acorn/ROOL Internet 5 stack.
REM Inspired by SockStats / SockStatsLite by Chris Williams.
REM Licence: MIT (see !Help)
REM ---------------------------------------------------------------------------
REM How it reads the stack
REM  ROD stack (Internet 7+): everything comes from Socket_Sysctl.
REM    net.route.0.0.iflist  -> per interface counters, names, addresses
REM    net.inet.tcp.stats    -> struct tcpstat (64 bit byte counters)
REM    net.inet.udp.stats / net.inet.ip.stats
REM  Old stack (Internet 5): interfaces from the same sysctl (older
REM    struct layout), protocol counters via Socket_InternalLookup, which is
REM    what SockStatsLite used. ROD no longer exports "_tcpstat" that way,
REM    which is why SockStatsLite fails there.
REM ---------------------------------------------------------------------------
ON ERROR PROCfatal(REPORT$+" (line "+STR$ERL+")")
PROCinit
ON ERROR PROCerror(REPORT$+" (line "+STR$ERL+")"):IF quit% THEN PROCshutdown:END
REPEAT
  PROCpoll
UNTIL quit%
PROCshutdown
END

REM ===========================================================================
REM Initialisation
REM ===========================================================================
DEF PROCinit
LOCAL j%
app$="NetStats":version$="1.05-rc1 (04 Oct 2026)"
quit%=FALSE:task%=0
DIM b% 1024, tmp% 256
REM Wimp
DIM msgs% 32
msgs%!0=&808C1:msgs%!4=&808C2:msgs%!8=&808C3:msgs%!12=0
SYS "Wimp_Initialise",380,&4B534154,app$,msgs% TO ,task%
PROCconstants
PROCdetect_stack
PROCalloc
PROCload_stats_table
PROCload_choices
PROCload_usage:PROCsession_reset
PROCcreate_windows
PROCcreate_menu
PROCiconbar
SYS "OS_ReadMonotonicTime" TO last%
next%=FNtadd(last%,interval%):usave%=last%
PROCsample(TRUE)
FOR j%=0 TO NWIN%-1
  IF wwasopen%(j%) THEN PROCopen(j%)
NEXT
IF stack%=0 THEN PROCreport("No Internet module is loaded, so there is nothing to measure. Start networking (!Boot > Configure > Network) and run "+app$+" again.")
ENDPROC

DEF PROCconstants
REM Socket SWIs, X form (works even if the module is not present)
XSysctl%=&6121A:XInternalLookup%=&61221:XSocketVersion%=&61222
CTL_NET%=4:PF_INET%=2:PF_ROUTE%=17:NET_RT_IFLIST%=3
RTM_NEWADDR%=&C:RTM_IFINFO%=&E
RTA_NETMASK%=4:RTA_IFP%=&10:RTA_IFA%=&20:NET_RT_DUMP%=1
AF_INET%=2:AF_LINK%=18
iffup%=1:iffloop%=8:iffrun%=&40
interval%=100:HN%=300:LH%=40:topm%=12
MAXIF%=24:MAXL%=400
REM window indices
WMON%=0:WIF%=1:WPROT%=2:WCONN%=3:WUSE%=4:WNET%=5:NWIN%=6
MAXDAYS%=400:MAXRT%=120
ENDPROC

DEF PROCalloc
DIM mib% 64, len% 8, nl% 64
DIM ifbuf% 32768:ifbufsz%=32768
DIM tcpbuf% 1024, udpbuf% 512, ipbuf% 512
DIM ifidx%(MAXIF%), ifname$(MAXIF%), ifflags%(MAXIF%), iftype%(MAXIF%)
DIM iflink%(MAXIF%), ifmtu%(MAXIF%), ifbaud(MAXIF%), ifmac$(MAXIF%)
DIM ifa4$(MAXIF%), ifa6$(MAXIF%), ifseen%(MAXIF%), iffirst%(MAXIF%)
DIM ib(MAXIF%), ob(MAXIF%), iblo%(MAXIF%), oblo%(MAXIF%), piblo%(MAXIF%), poblo%(MAXIF%)
DIM ipk(MAXIF%), opk(MAXIF%), ierr(MAXIF%), oerr(MAXIF%), idrop(MAXIF%), odrop(MAXIF%), coll(MAXIF%)
DIM rin(MAXIF%), rout(MAXIF%), g6%(7), cw$(10)
ifn%=0:ifok%=FALSE:iferr$=""
DIM hin(HN%), hout(HN%):hpos%=0:hcount%=0
DIM L$(NWIN%-1,MAXL%), nlines%(NWIN%-1), tab%(NWIN%-1,8), wh%(NWIN%-1), wopen%(NWIN%-1)
DIM lastn%(NWIN%-1), P$(NWIN%-1,MAXL%), pn%(NWIN%-1)
REM data usage: one entry per day, plus this session
DIM udate$(MAXDAYS%), udin(MAXDAYS%), udout(MAXDAYS%):un%=0
sessin=0:sessout=0:sessstart$="":usave%=0
REM chosen interface ("" = all) and the menu of interfaces
selif$="":DIM ifmname$(MAXIF%+1)
REM routes and network settings
DIM rtbuf% 32768, vbuf% 256:rtn%=0:DIM rt$(MAXRT%):gw4$="":gw6$="":rterr$="":netstamp%=0
totin=0:totout=0:sumib=0:sumob=0:nactive%=0:srcnote$=""
bits%=FALSE:loopback%=FALSE:autoconn%=FALSE:ibrates%=TRUE
DIM wpos%(NWIN%-1,3), wposok%(NWIN%-1), wwasopen%(NWIN%-1)
connstamp%=0:connbusy%=FALSE:conntask%=0:conntxt%=&4E537478:crn%=0:cpart$=""
MAXCR%=600:DIM cr$(MAXCR%)
ENDPROC

REM ---------------------------------------------------------------------------
REM Which stack is loaded?  stack%: 0 none, 1 old Internet 5, 2 ROD Internet 7
REM ---------------------------------------------------------------------------
DEF PROCdetect_stack
LOCAL f%, base%, v%
stack%=0:stackname$="(no Internet module)":stackver%=0:modbase%=0
SYS "XOS_Module",18,"Internet" TO ,,,base% ;f%
IF f% AND 1 THEN ENDPROC
modbase%=base%
stackname$=FNmodhelp(base%)
REM Socket_Version gives the module version * 100 on both stacks
SYS XSocketVersion% TO v% ;f%
IF (f% AND 1)=0 AND v%>=100 AND v%<10000 THEN stackver%=v%
IF stackver%=0 THEN stackver%=FNver_from_help(stackname$)
IF stackver%>=700 THEN stack%=2 ELSE stack%=1
ENDPROC

REM if the Internet module has been reloaded or killed, start again
DEF PROCcheck_module
LOCAL f%, base%
SYS "XOS_Module",18,"Internet" TO ,,,base% ;f%
IF f% AND 1 THEN base%=0
IF base%<>modbase% THEN
  PROCdetect_stack:leg_done%=FALSE:stfirst%=TRUE
  IF ifn%>0 THEN FOR f%=0 TO ifn%-1:iffirst%(f%)=TRUE:NEXT
ENDIF
ENDPROC

DEF FNmodhelp(base%)
LOCAL s$, i%, c%, sp%
IF base%!20=0 THEN ="Internet"
i%=base%+base%!20:sp%=FALSE
WHILE ?i%<>0 AND LEN(s$)<200
  c%=?i%
  IF c%=9 OR c%=32 THEN
    IF NOT sp% THEN s$+=" "
    sp%=TRUE
  ELSE
    s$+=CHR$c%:sp%=FALSE
  ENDIF
  i%+=1
ENDWHILE
=s$

DEF FNver_from_help(h$)
LOCAL i%, v
i%=1
WHILE i%<=LEN(h$) AND v=0
  IF MID$(h$,i%,1)>="0" AND MID$(h$,i%,1)<="9" THEN v=VAL(MID$(h$,i%))
  i%+=1
ENDWHILE
=INT(v*100+0.5)

REM ===========================================================================
REM Main loop
REM ===========================================================================
DEF PROCpoll
LOCAL reason%, now%
SYS "Wimp_PollIdle",&30,b%,next% TO reason%
CASE reason% OF
  WHEN 0
    SYS "OS_ReadMonotonicTime" TO now%
    IF FNtdiff(now%,next%)>=0 THEN
      PROCsample(FALSE)
      next%=FNtadd(now%,interval%)
    ENDIF
  WHEN 1:PROCredraw(!b%)
  WHEN 2:SYS "Wimp_OpenWindow",,b%
  WHEN 3:PROCclose(!b%)
  WHEN 6:PROCclick
  WHEN 8:SYS "Wimp_ProcessKey",b%!24
  WHEN 9:PROCmenu_select
  WHEN 17,18
    CASE b%!16 OF
      WHEN 0:quit%=TRUE
      WHEN &808C1,&808C2,&808C3:PROCtw_message(reason%)
    ENDCASE
ENDCASE
ENDPROC

DEF PROCshutdown
PROCtw_kill
PROCsave_choices
PROCsave_usage
SYS "XWimp_CloseDown",task%,&4B534154
ENDPROC

DEF PROCfatal(e$)
ON ERROR OFF
!tmp%=255:$(tmp%+4)=LEFT$(e$,200)+CHR$0
SYS "XWimp_ReportError",tmp%,1,"NetStats"
IF task% THEN SYS "XWimp_CloseDown",task%,&4B534154
END
ENDPROC

DEF PROCerror(e$)
LOCAL r%
!tmp%=255:$(tmp%+4)=LEFT$(e$,180)+CHR$0
SYS "Wimp_ReportError",tmp%,3,"NetStats (Cancel quits)" TO ,r%
IF r%=2 THEN quit%=TRUE
ENDPROC

DEF PROCreport(e$)
!tmp%=0:$(tmp%+4)=LEFT$(e$,240)+CHR$0
SYS "Wimp_ReportError",tmp%,1,app$
ENDPROC

REM ===========================================================================
REM Sampling
REM ===========================================================================
DEF PROCsample(first%)
LOCAL now%, dt, j%
SYS "OS_ReadMonotonicTime" TO now%
dt=FNtdiff(now%,last%)/100:IF dt<=0 THEN dt=1
IF first% THEN dt=1
PROCcheck_module
IF stack% THEN
  PROCread_ifaces(dt)
  PROCread_stats(dt)
ENDIF
PROCtotals
PROCusage_add(dt)
PROCiconbar_text
hin(hpos%)=totin:hout(hpos%)=totout
hpos%=(hpos%+1) MOD HN%:IF hcount%<HN% THEN hcount%+=1
IF first% THEN hcount%=0
last%=now%
IF wopen%(WNET%) AND FNtdiff(now%,netstamp%)>=1000 THEN PROCbuild_one(WNET%)
FOR j%=0 TO NWIN%-1
  IF wopen%(j%) THEN
    IF j%<>WCONN% AND j%<>WNET% THEN PROCbuild_one(j%)
    IF j%<>WCONN% THEN PROCrefresh(j%)
  ENDIF
NEXT
IF FNtdiff(now%,usave%)>=30000 THEN PROCsave_usage:usave%=now%
IF wopen%(WCONN%) AND autoconn% THEN
  IF FNtdiff(now%,connstamp%)>=1000 THEN PROCconnections
ENDIF
ENDPROC

REM Sum the interfaces (or fall back to TCP byte counts)
DEF PROCtotals
LOCAL j%
totin=0:totout=0:sumib=0:sumob=0:nactive%=0
IF ifok% THEN
  srcnote$=""
  IF selif$<>"" AND FNfindname(selif$)<0 THEN srcnote$=selif$+" is not present"
  j%=0
  WHILE j%<ifn%
    IF FNcounted(j%) THEN
      totin+=rin(j%):totout+=rout(j%):sumib+=ib(j%):sumob+=ob(j%)
      IF (ifflags%(j%) AND iffup%) THEN nactive%+=1
    ENDIF
    j%+=1
  ENDWHILE
ELSE
  IF tcpok% THEN
    totin=st_rate(tcp_rcvbyte%):totout=st_rate(tcp_sndbyte%)
    sumib=st_val(tcp_rcvbyte%):sumob=st_val(tcp_sndbyte%)
    srcnote$="TCP data only (interface list unavailable)"
  ENDIF
ENDIF
ENDPROC

REM ---------------------------------------------------------------------------
REM sysctl helper: returns bytes written, or -1 on error (sets sysctl_err$)
REM ---------------------------------------------------------------------------
DEF FNsysctl(mib%, n%, buf%, size%)
LOCAL f%, e%
!len%=size%
SYS XSysctl%,mib%,n%,buf%,len%,0,0 TO e% ;f%
IF f% AND 1 THEN sysctl_err$=FNerrstr(e%):=-1
=!len%

DEF FNerrstr(e%)
IF e%=0 THEN ="error"
=FNstr0(e%+4)

DEF PROCmib(m0%,m1%,m2%,m3%,m4%,m5%)
mib%!0=m0%:mib%!4=m1%:mib%!8=m2%:mib%!12=m3%:mib%!16=m4%:mib%!20=m5%
ENDPROC

REM ---------------------------------------------------------------------------
REM Interfaces: net.route.0.0.iflist.0
REM ---------------------------------------------------------------------------
DEF PROCread_ifaces(dt)
LOCAL n%, j%
PROCmib(CTL_NET%,PF_ROUTE%,0,0,NET_RT_IFLIST%,0)
n%=FNsysctl(mib%,6,ifbuf%,ifbufsz%)
IF n%<0 THEN
  ifok%=FALSE:iferr$=sysctl_err$
  IF ifn%>0 THEN FOR j%=0 TO ifn%-1:iffirst%(j%)=TRUE:rin(j%)=0:rout(j%)=0:NEXT
  ENDPROC
ENDIF
ifok%=TRUE:iferr$=""
PROCparse_iflist(ifbuf%,n%)
j%=0
WHILE j%<ifn%
  IF iffirst%(j%) THEN
    rin(j%)=0:rout(j%)=0:iffirst%(j%)=FALSE
  ELSE
    rin(j%)=FNdelta(iblo%(j%),piblo%(j%))/dt
    rout(j%)=FNdelta(oblo%(j%),poblo%(j%))/dt
  ENDIF
  piblo%(j%)=iblo%(j%):poblo%(j%)=oblo%(j%)
  j%+=1
ENDWHILE
ENDPROC

REM Walk the routing messages. rod% layout = OpenBSD 6.8, else 4.4BSD/FreeBSD
DEF PROCparse_iflist(buf%, n%)
LOCAL p%, ml%, ty%, j%, hdr%, idx%, addrs%, d%, k%
IF ifn%>0 THEN FOR j%=0 TO ifn%-1:ifseen%(j%)=FALSE:ifa4$(j%)="":ifa6$(j%)="":NEXT
p%=buf%
WHILE p%+4<=buf%+n%
  ml%=FNu16(p%):ty%=p%?3
  IF ml%<4 THEN
    p%=buf%+n%
  ELSE
    IF ty%=RTM_IFINFO% THEN PROCparse_ifinfo(p%)
    IF ty%=RTM_NEWADDR% THEN PROCparse_newaddr(p%)
    p%+=ml%
  ENDIF
ENDWHILE
REM drop interfaces that have gone
k%=0
j%=0
WHILE j%<ifn%
  IF ifseen%(j%) THEN
    IF k%<>j% THEN PROCcopy_if(j%,k%)
    k%+=1
  ENDIF
  j%+=1
ENDWHILE
ifn%=k%
ENDPROC

DEF PROCparse_ifinfo(p%)
LOCAL hdr%, idx%, addrs%, flags%, d%, j%
IF stack%=2 THEN
  hdr%=FNu16(p%+4):idx%=FNu16(p%+6):addrs%=p%!12:flags%=p%!16:d%=p%+24
ELSE
  addrs%=p%!4:flags%=p%!8:idx%=FNu16(p%+12):d%=p%+16:hdr%=96
ENDIF
j%=FNslot(idx%):IF j%<0 THEN ENDPROC
ifseen%(j%)=TRUE:ifflags%(j%)=flags%:iftype%(j%)=d%?0
IF stack%=2 THEN
  iflink%(j%)=d%?3:ifmtu%(j%)=d%!4:ifbaud(j%)=FNu64(d%+16)
  ipk(j%)=FNu64(d%+24):ierr(j%)=FNu64(d%+32):opk(j%)=FNu64(d%+40)
  oerr(j%)=FNu64(d%+48):coll(j%)=FNu64(d%+56)
  ib(j%)=FNu64(d%+64):ob(j%)=FNu64(d%+72)
  idrop(j%)=FNu64(d%+96):odrop(j%)=FNu64(d%+104)
  iblo%(j%)=d%!64:oblo%(j%)=d%!72
ELSE
  iflink%(j%)=-1:ifmtu%(j%)=d%!8:ifbaud(j%)=FNu32(d%!16)
  ipk(j%)=FNu32(d%!20):ierr(j%)=FNu32(d%!24):opk(j%)=FNu32(d%!28)
  oerr(j%)=FNu32(d%!32):coll(j%)=FNu32(d%!36)
  ib(j%)=FNu32(d%!40):ob(j%)=FNu32(d%!44)
  idrop(j%)=FNu32(d%!56):odrop(j%)=-1
  iblo%(j%)=d%!40:oblo%(j%)=d%!44
ENDIF
PROCwalk_sa(p%+hdr%,addrs%,j%,FALSE)
ENDPROC

DEF PROCparse_newaddr(p%)
LOCAL hdr%, idx%, addrs%, j%
IF stack%=2 THEN
  hdr%=FNu16(p%+4):idx%=FNu16(p%+6):addrs%=p%!12
ELSE
  addrs%=p%!4:idx%=FNu16(p%+12):hdr%=20
ENDIF
j%=FNfind(idx%):IF j%<0 THEN ENDPROC
PROCwalk_sa(p%+hdr%,addrs%,j%,TRUE)
ENDPROC

REM Step through the sockaddrs that follow a message header, in RTA_ order
DEF PROCwalk_sa(sa%, addrs%, j%, isaddr%)
LOCAL bit%, l%, fam%, a$, m%, mfam%
m%=0
FOR bit%=0 TO 11
  IF addrs% AND (1<<bit%) THEN
    l%=?sa%:fam%=sa%?1
    IF (1<<bit%)=RTA_NETMASK% THEN m%=sa%
    IF (1<<bit%)=RTA_IFP% AND fam%=AF_LINK% THEN PROCread_sdl(sa%,j%)
    IF (1<<bit%)=RTA_IFA% AND isaddr% THEN
      IF fam%=AF_INET% THEN
        a$=FNip4(sa%+4)
        IF m% THEN a$+="/"+STR$FNmaskbits(m%,4,4)
        ifa4$(j%)=FNaddto(ifa4$(j%),a$)
      ENDIF
      IF fam%=24 OR fam%=28 THEN
        a$=FNip6(sa%+8,ifname$(j%))
        IF m% THEN a$+="/"+STR$FNmaskbits(m%,8,16)
        ifa6$(j%)=FNaddto(ifa6$(j%),a$)
      ENDIF
    ENDIF
    IF l%=0 THEN sa%+=4 ELSE sa%+=((l%-1) OR 3)+1
  ENDIF
NEXT
ENDPROC

DEF FNaddto(s$, a$)
IF LEN(s$)+LEN(a$)>230 THEN =s$
IF s$="" THEN =a$
=s$+", "+a$

REM sockaddr_dl: name and hardware address
DEF PROCread_sdl(sa%, j%)
LOCAL nn%, al%, i%, s$
nn%=sa%?5:al%=sa%?6
IF nn%>0 AND nn%<=16 THEN
  s$="":FOR i%=0 TO nn%-1:s$+=CHR$(sa%?(8+i%)):NEXT
  ifname$(j%)=s$
ENDIF
s$=""
IF al%>0 AND al%<=8 THEN
  FOR i%=0 TO al%-1
    s$+=RIGHT$("0"+STR$~(sa%?(8+nn%+i%)),2)
    IF i%<al%-1 THEN s$+=":"
  NEXT
ENDIF
ifmac$(j%)=FNlower(s$)
ENDPROC

REM count the set bits of a netmask (sockaddr may be truncated)
DEF FNmaskbits(m%, off%, nb%)
LOCAL l%, i%, c%, bb%, n%
l%=?m%:n%=0
FOR i%=0 TO nb%-1
  IF off%+i%<l% THEN
    c%=m%?(off%+i%)
    FOR bb%=7 TO 0 STEP -1
      IF c% AND (1<<bb%) THEN n%+=1
    NEXT
  ENDIF
NEXT
=n%

REM is interface j% included in the totals?
DEF FNcounted(j%)
IF selif$<>"" THEN =(ifname$(j%)=selif$)
=(loopback% OR (ifflags%(j%) AND iffloop%)=0)

DEF FNfindname(n$)
LOCAL j%
j%=0
WHILE j%<ifn%
  IF ifname$(j%)=n$ THEN =j%
  j%+=1
ENDWHILE
=-1

DEF FNslot(idx%)
LOCAL j%
j%=FNfind(idx%)
IF j%>=0 THEN =j%
IF ifn%>=MAXIF% THEN =-1
j%=ifn%:ifn%+=1
ifidx%(j%)=idx%:ifname$(j%)="if"+STR$idx%:ifmac$(j%)="":iffirst%(j%)=TRUE
ifa4$(j%)="":ifa6$(j%)=""
=j%

DEF FNfind(idx%)
LOCAL j%
j%=0
WHILE j%<ifn%
  IF ifidx%(j%)=idx% THEN =j%
  j%+=1
ENDWHILE
=-1

DEF PROCcopy_if(f%, t%)
ifidx%(t%)=ifidx%(f%):ifname$(t%)=ifname$(f%):ifflags%(t%)=ifflags%(f%)
iftype%(t%)=iftype%(f%):iflink%(t%)=iflink%(f%):ifmtu%(t%)=ifmtu%(f%)
ifbaud(t%)=ifbaud(f%):ifmac$(t%)=ifmac$(f%):ifa4$(t%)=ifa4$(f%):ifa6$(t%)=ifa6$(f%)
ifseen%(t%)=ifseen%(f%):iffirst%(t%)=iffirst%(f%)
ib(t%)=ib(f%):ob(t%)=ob(f%):iblo%(t%)=iblo%(f%):oblo%(t%)=oblo%(f%)
piblo%(t%)=piblo%(f%):poblo%(t%)=poblo%(f%)
ipk(t%)=ipk(f%):opk(t%)=opk(f%):ierr(t%)=ierr(f%):oerr(t%)=oerr(f%)
idrop(t%)=idrop(f%):odrop(t%)=odrop(f%):coll(t%)=coll(f%)
rin(t%)=rin(f%):rout(t%)=rout(f%)
ENDPROC

REM ---------------------------------------------------------------------------
REM Protocol statistics
REM st_rod%  = offset in the ROD struct when 64 bit fields are 4-byte aligned
REM st_rod8% = offset when they are 8-byte aligned (layout chosen at run time
REM            from the size the stack returns: tcpstat is 536 or 560 bytes)
REM st_64%   = field is u_int64_t on ROD
REM st_leg%  = word index in the old stack's struct (-1 = not present)
REM ---------------------------------------------------------------------------
DEF PROCload_stats_table
LOCAL i%, g$
RESTORE +0
READ NST%
DIM st_label$(NST%), st_grp%(NST%), st_rod%(NST%), st_rod8%(NST%), st_64%(NST%), st_leg6%(NST%)
DIM st_val(NST%), st_rate(NST%), st_lo%(NST%), st_plo%(NST%), st_ok%(NST%), st_first%(NST%)
FOR i%=0 TO NST%-1
  READ g$, st_label$(i%), st_rod%(i%), st_rod8%(i%), st_64%(i%), st_leg6%(i%)
  st_grp%(i%)=INSTR("TUI",g$)-1:st_first%(i%)=TRUE
  IF st_label$(i%)="Data bytes sent" THEN tcp_sndbyte%=i%
  IF st_label$(i%)="Data bytes received in order" THEN tcp_rcvbyte%=i%
NEXT
tcpok%=FALSE:udpok%=FALSE:ipok%=FALSE:tcplayout$="":stfirst%=TRUE:leg_done%=FALSE
statnote$=""
ENDPROC
DATA 30
DATA T,Connections initiated,0,0,0,0
DATA T,Connections accepted,4,4,0,1
DATA T,Connections established,8,8,0,2
DATA T,Connections dropped,12,12,0,3
DATA T,Embryonic connections dropped,16,16,0,4
DATA T,Connections closed,20,20,0,5
DATA T,Dropped by retransmit timeout,36,36,0,9
DATA T,Retransmit timeouts,40,40,0,10
DATA T,Dropped by keepalive,60,60,0,14
DATA T,Packets sent,64,64,0,15
DATA T,Data packets sent,68,68,0,16
DATA T,Data bytes sent,72,72,1,17
DATA T,Data packets retransmitted,80,80,0,18
DATA T,Data bytes retransmitted,84,88,1,19
DATA T,Packets received,120,124,0,25
DATA T,Packets received in order,124,128,0,26
DATA T,Data bytes received in order,128,136,1,27
DATA T,Packets with bad checksum,136,144,0,28
DATA T,Duplicate packets received,156,164,0,31
DATA T,Out-of-order packets received,180,192,0,35
DATA T,Segments to closed ports,256,276,0,-1
DATA U,Datagrams received,0,0,0,0
DATA U,Datagrams sent,44,44,0,8
DATA U,Bad checksum,8,8,0,2
DATA U,No socket on port,20,20,0,4
DATA U,Dropped (socket full),32,32,0,6
DATA I,Packets received,0,0,0,0
DATA I,Delivered to upper layers,52,52,0,13
DATA I,Packets sent,56,56,0,14
DATA I,Output drops / no route,60,60,0,15

DEF PROCread_stats(dt)
LOCAL i%, n%, p%, base%, lay8%, ok%, f%
IF stack%=2 THEN
  PROCmib(CTL_NET%,PF_INET%,6,21,0,0):n%=FNsysctl(mib%,4,tcpbuf%,1024)
  tcpok%=(n%>=280)
  lay8%=(n%=560)
  tcplayout$=""
  IF tcpok% AND n%<>536 AND n%<>560 THEN tcplayout$="unexpected TCP statistics size ("+STR$n%+" bytes); TCP figures may be wrong"
  IF n%<0 THEN tcplayout$="TCP statistics unavailable: "+sysctl_err$
  PROCmib(CTL_NET%,PF_INET%,17,5,0,0):n%=FNsysctl(mib%,4,udpbuf%,512):udpok%=(n%>=48)
  PROCmib(CTL_NET%,PF_INET%,0,33,0,0):n%=FNsysctl(mib%,4,ipbuf%,512):ipok%=(n%>=64)
ELSE
  PROClegacy_lookup
ENDIF
FOR i%=0 TO NST%-1
  ok%=FALSE
  CASE st_grp%(i%) OF
    WHEN 0:ok%=tcpok%:base%=tcpbuf%:IF stack%=1 THEN base%=leg_tcp%
    WHEN 1:ok%=udpok%:base%=udpbuf%:IF stack%=1 THEN base%=leg_udp%
    WHEN 2:ok%=ipok%:base%=ipbuf%:IF stack%=1 THEN base%=leg_ip%
  ENDCASE
  IF stack%=1 AND st_leg6%(i%)<0 THEN ok%=FALSE
  st_ok%(i%)=ok%
  IF ok% THEN
    IF stack%=2 THEN
      IF lay8% AND st_grp%(i%)=0 THEN p%=base%+st_rod8%(i%) ELSE p%=base%+st_rod%(i%)
      IF st_64%(i%) THEN st_val(i%)=FNu64(p%) ELSE st_val(i%)=FNu32(!p%)
    ELSE
      p%=base%+4*st_leg6%(i%):st_val(i%)=FNu32(!p%)
    ENDIF
    st_lo%(i%)=!p%
    IF stfirst% OR st_first%(i%) THEN st_rate(i%)=0 ELSE st_rate(i%)=FNdelta(st_lo%(i%),st_plo%(i%))/dt
    st_plo%(i%)=st_lo%(i%):st_first%(i%)=FALSE
  ELSE
    st_first%(i%)=TRUE:st_rate(i%)=0
  ENDIF
NEXT
stfirst%=FALSE
ENDPROC

REM Old stack: find the counters with Socket_InternalLookup (12 byte nlist)
DEF PROClegacy_lookup
LOCAL f%, e%, i%
IF leg_done% THEN ENDPROC
leg_done%=TRUE:leg_tcp%=0:leg_udp%=0:leg_ip%=0
$(tmp%)="_tcpstat"+CHR$0:$(tmp%+16)="_udpstat"+CHR$0:$(tmp%+32)="_ipstat"+CHR$0
FOR i%=0 TO 2:nl%!(i%*12)=tmp%+i%*16:nl%!(i%*12+4)=0:nl%!(i%*12+8)=0:NEXT
nl%!36=0:nl%!40=0:nl%!44=0
SYS XInternalLookup%,0,nl% TO e% ;f%
IF (f% AND 1)=0 THEN
  leg_tcp%=nl%!8:leg_udp%=nl%!20:leg_ip%=nl%!32
ENDIF
tcpok%=(leg_tcp%<>0):udpok%=(leg_udp%<>0):ipok%=(leg_ip%<>0)
ENDPROC

REM ===========================================================================
REM Number helpers
REM ===========================================================================
REM monotonic time arithmetic that survives the 32-bit wrap (after ~248 days)
DEF FNtdiff(a%, b%)=FNwrap(a%-b%)
DEF FNtadd(a%, b%)=FNwrap(a%+b%)
DEF FNwrap(x)
IF x>2147483647 THEN =x-4294967296
IF x<-2147483648 THEN =x+4294967296
=x

DEF FNu16(p%)=p%?0+256*p%?1
DEF FNu32(x%)
IF x%<0 THEN =x%+4294967296
=x%
DEF FNu64(p%)=FNu32(!p%)+4294967296*FNu32(p%!4)

REM difference of two 32-bit counters, allowing for one wrap
DEF FNdelta(n%, o%)
LOCAL d
d=FNu32(n%)-FNu32(o%)
IF d<0 THEN d+=4294967296
=d

DEF FNstr0(p%)
LOCAL s$
WHILE ?p%<>0 AND LEN(s$)<160:s$+=CHR$?p%:p%+=1:ENDWHILE
=s$

DEF FNlower(s$)
LOCAL i%, c%, r$
IF s$="" THEN =""
FOR i%=1 TO LEN(s$)
  c%=ASC(MID$(s$,i%,1)):IF c%>=65 AND c%<=90 THEN c%+=32
  r$+=CHR$c%
NEXT
=r$

REM integer with thousands separators (works beyond 2^31)
DEF FNnum(x)
LOCAL s$, hi, lo, r$, i%
IF x<0 THEN ="-"
IF x>=2E15 THEN =STR$(x)
REM INT() only works below 2^31, so split big numbers into millions
IF x<1E9 THEN
  s$=STR$(INT(x+0.5))
ELSE
  hi=INT(x/1E6):lo=INT(x-hi*1E6+0.5)
  IF lo>=1E6 THEN hi+=1:lo-=1E6
  s$=STR$(hi)+RIGHT$("000000"+STR$(lo),6)
ENDIF
r$=""
FOR i%=LEN(s$) TO 1 STEP -1
  r$=MID$(s$,i%,1)+r$
  IF (LEN(s$)-i%+1) MOD 3=0 AND i%>1 THEN r$=","+r$
NEXT
=r$

REM one decimal place below 100, otherwise whole numbers
DEF FNdp(v)
LOCAL a
IF v>=99.95 THEN =STR$(INT(v+0.5))
a=INT(v*10+0.5)
=STR$(INT(a/10))+"."+STR$(a-10*INT(a/10))

DEF FNbytes(x)
IF x<0 THEN ="-"
IF x<1024 THEN =STR$(INT(x))+" B"
IF x<1048576 THEN =FNdp(x/1024)+" KB"
IF x<1073741824 THEN =FNdp(x/1048576)+" MB"
IF x<1099511627776 THEN =FNdp(x/1073741824)+" GB"
=FNdp(x/1099511627776)+" TB"

REM a rate in bytes/second, shown as bytes or bits depending on the choice
DEF FNrate(r)
IF r<0 THEN ="-"
IF bits% THEN =FNbitrate(r*8)
IF r<1024 THEN =STR$(INT(r+0.5))+" B/s"
IF r<1048576 THEN =FNdp(r/1024)+" KB/s"
IF r<1073741824 THEN =FNdp(r/1048576)+" MB/s"
=FNdp(r/1073741824)+" GB/s"

DEF FNbitrate(b)
IF b<1000 THEN =STR$(INT(b+0.5))+" bit/s"
IF b<1E6 THEN =FNdp(b/1000)+" kbit/s"
IF b<1E9 THEN =FNdp(b/1E6)+" Mbit/s"
=FNdp(b/1E9)+" Gbit/s"

DEF FNspeed(b)
IF b<=0 THEN =""
IF b<1E6 THEN =FNdp(b/1000)+" kbit/s"
IF b<1E9 THEN =FNdp(b/1E6)+" Mbit/s"
=FNdp(b/1E9)+" Gbit/s"

DEF FNip4(p%)=STR$(p%?0)+"."+STR$(p%?1)+"."+STR$(p%?2)+"."+STR$(p%?3)

REM IPv6 text form with the longest run of zero groups shortened to ::
DEF FNip6(p%, ifn$)
LOCAL i%, bs%, bl%, cs%, cl%, s$, ll%
ll%=(p%?0=&FE AND (p%?1 AND &C0)=&80)
FOR i%=0 TO 7:g6%(i%)=p%?(2*i%)*256+p%?(2*i%+1):NEXT
REM KAME stores the scope (interface index) in group 1 of link-local addresses
IF ll% THEN g6%(1)=0
bs%=-1:bl%=0:cs%=-1:cl%=0
FOR i%=0 TO 7
  IF g6%(i%)=0 THEN
    IF cs%<0 THEN cs%=i%:cl%=0
    cl%+=1
    IF cl%>bl% THEN bl%=cl%:bs%=cs%
  ELSE
    cs%=-1:cl%=0
  ENDIF
NEXT
IF bl%<2 THEN bs%=-1
s$=""
FOR i%=0 TO 7
  IF i%=bs% THEN
    s$+="::":i%+=bl%-1
  ELSE
    IF s$<>"" AND RIGHT$(s$,1)<>":" THEN s$+=":"
    s$+=FNlower(STR$~g6%(i%))
  ENDIF
NEXT
IF ll% AND ifn$<>"" THEN s$+="%"+ifn$
=s$

DEF FNiftype(t%)
CASE t% OF
  WHEN 6:="Ethernet"
  WHEN 24:="Loopback"
  WHEN 71:="Wireless"
  WHEN 23:="PPP"
  WHEN 131:="Tunnel"
  WHEN 209:="Bridge"
  WHEN 135:="VLAN"
  WHEN 245:="Packet log"
  WHEN 246:="pfsync"
  WHEN 247:="Packet flow"
  WHEN 248:="Encapsulation"
ENDCASE
="type "+STR$t%

DEF FNlink(j%)
LOCAL s$, l%
IF (ifflags%(j%) AND iffup%)=0 THEN ="down (disabled)"
l%=iflink%(j%)
CASE l% OF
  WHEN -1:IF ifflags%(j%) AND iffrun% THEN s$="up" ELSE s$="up, not running"
  WHEN 0:s$="up"
  WHEN 1:s$="link invalid"
  WHEN 2,3:s$="no link (cable/carrier)"
  WHEN 4:s$="up, link active"
  WHEN 5:s$="up, half duplex"
  WHEN 6:s$="up, full duplex"
  OTHERWISE:s$="link state "+STR$l%
ENDCASE
=s$

REM ===========================================================================
REM Text for the windows. Columns are separated by TAB; a leading "#" marks
REM a heading line, "~" a note in grey.
REM ===========================================================================
REM rebuild the text of the open windows only
DEF PROCbuild_text
LOCAL j%
FOR j%=0 TO NWIN%-1
  IF wopen%(j%) THEN PROCbuild_one(j%)
NEXT
ENDPROC

DEF PROCbuild_one(j%)
CASE j% OF
  WHEN WIF%:PROCtext_ifaces
  WHEN WPROT%:PROCtext_stats
  WHEN WUSE%:PROCtext_usage
  WHEN WNET%:PROCread_routes:PROCtext_net:SYS "OS_ReadMonotonicTime" TO netstamp%
ENDCASE
ENDPROC

DEF PROCaddl(w%, s$)
IF nlines%(w%)>=MAXL% THEN ENDPROC
L$(w%,nlines%(w%))=s$:nlines%(w%)+=1
ENDPROC

DEF PROCtext_ifaces
LOCAL j%, t$, T$
T$=CHR$9
nlines%(WIF%)=0
PROCaddl(WIF%,"~Stack: "+stackname$)
IF stack%=0 THEN PROCaddl(WIF%,"~No Internet module loaded"):ENDPROC
IF NOT ifok% THEN PROCaddl(WIF%,"~Interface list not available: "+iferr$):ENDPROC
IF ifn%=0 THEN PROCaddl(WIF%,"~No interfaces reported")
j%=0
WHILE j%<ifn%
  t$="#"+ifname$(j%)+"   "+FNiftype(iftype%(j%))+", "+FNlink(j%)
  PROCaddl(WIF%,t$)
  t$="Settings"+T$+"MTU "+STR$ifmtu%(j%)
  IF ifbaud(j%)>0 THEN t$+=",  "+FNspeed(ifbaud(j%))
  IF ifmac$(j%)<>"" THEN t$+=",  hardware "+ifmac$(j%)
  PROCaddl(WIF%,t$)
  IF ifa4$(j%)<>"" THEN PROCaddl(WIF%,"IPv4"+T$+ifa4$(j%))
  IF ifa6$(j%)<>"" THEN PROCaddl(WIF%,"IPv6"+T$+ifa6$(j%))
  PROCaddl(WIF%,"~"+T$+T$+"Rate"+T$+"Total"+T$+"Packets"+T$+"Errors"+T$+"Drops")
  PROCaddl(WIF%,"Receive"+T$+T$+FNrate(rin(j%))+T$+FNbytes(ib(j%))+T$+FNnum(ipk(j%))+T$+FNnum(ierr(j%))+T$+FNnum(idrop(j%)))
  PROCaddl(WIF%,"Send"+T$+T$+FNrate(rout(j%))+T$+FNbytes(ob(j%))+T$+FNnum(opk(j%))+T$+FNnum(oerr(j%))+T$+FNnum(odrop(j%)))
  IF coll(j%)>0 THEN PROCaddl(WIF%,"Collisions"+T$+T$+T$+T$+FNnum(coll(j%)))
  PROCaddl(WIF%,"")
  j%+=1
ENDWHILE
ENDPROC

DEF PROCtext_stats
LOCAL i%, g%, T$
T$=CHR$9
nlines%(WPROT%)=0
PROCaddl(WPROT%,"~Stack: "+stackname$)
IF stack%=0 THEN ENDPROC
IF tcplayout$<>"" THEN PROCaddl(WPROT%,"~Note: "+tcplayout$)
g%=-1
FOR i%=0 TO NST%-1
  IF st_grp%(i%)<>g% THEN
    g%=st_grp%(i%)
    IF i%>0 THEN PROCaddl(WPROT%,"")
    CASE g% OF
      WHEN 0:PROCaddl(WPROT%,"#TCP"+T$+"Total"+T$+"Per second")
      WHEN 1:PROCaddl(WPROT%,"#UDP"+T$+"Total"+T$+"Per second")
      WHEN 2:PROCaddl(WPROT%,"#IP (version 4)"+T$+"Total"+T$+"Per second")
    ENDCASE
  ENDIF
  IF st_ok%(i%) THEN
    IF st_64%(i%) OR INSTR(st_label$(i%),"bytes") THEN
      PROCaddl(WPROT%,st_label$(i%)+T$+FNbytes(st_val(i%))+T$+FNrate(st_rate(i%)))
    ELSE
      PROCaddl(WPROT%,st_label$(i%)+T$+FNnum(st_val(i%))+T$+FNdp(st_rate(i%)))
    ENDIF
  ELSE
    PROCaddl(WPROT%,st_label$(i%)+T$+"n/a"+T$+"")
  ENDIF
NEXT
ENDPROC

REM ===========================================================================
REM Windows
REM ===========================================================================
DEF PROCcreate_windows
LOCAL i%
nwin%=0
wh%(WMON%)=FNwindow("NetStats",600,300,1600,1200,&A7000002,200,160)
wh%(WIF%)=FNwindow("Interfaces",1060,640,1400,4000,&BF000002,0,0)
wh%(WPROT%)=FNwindow("Protocol statistics",820,640,1000,4000,&BF000002,0,0)
wh%(WCONN%)=FNwindow("Connections",1300,560,1400,8000,&BF000002,0,0)
wh%(WUSE%)=FNwindow("Data usage",900,600,1000,4000,&BF000002,0,0)
wh%(WNET%)=FNwindow("Network",1060,560,1400,8000,&BF000002,0,0)
REM tab stops (negative = right aligned at that x)
tab%(WIF%,0)=16:tab%(WIF%,1)=150:tab%(WIF%,2)=-380:tab%(WIF%,3)=-560:tab%(WIF%,4)=-770:tab%(WIF%,5)=-900:tab%(WIF%,6)=-1030
tab%(WPROT%,0)=16:tab%(WPROT%,1)=-600:tab%(WPROT%,2)=-790
REM queue columns right-aligned with room for their headings (~110 wide)
tab%(WCONN%,0)=16:tab%(WCONN%,1)=100:tab%(WCONN%,2)=470:tab%(WCONN%,3)=840:tab%(WCONN%,4)=-1130:tab%(WCONN%,5)=-1270
tab%(WUSE%,0)=16:tab%(WUSE%,1)=-520:tab%(WUSE%,2)=-700:tab%(WUSE%,3)=-880
tab%(WNET%,0)=16:tab%(WNET%,1)=220:tab%(WNET%,2)=420:tab%(WNET%,3)=780:tab%(WNET%,4)=880
PROCcreate_info
ENDPROC

DEF FNwindow(t$, w%, h%, ew%, eh%, flags%, mw%, mh%)
LOCAL hd%, ind%, x%, y%
DIM ind% 40:$ind%=t$
x%=160+64*nwin%:y%=1100-48*nwin%:nwin%+=1
b%!0=x%:b%!4=y%-h%:b%!8=x%+w%:b%!12=y%:b%!16=0:b%!20=0:b%!24=-1
b%!28=flags%
b%?32=7:b%?33=2:b%?34=7:b%?35=0:b%?36=3:b%?37=1:b%?38=12:b%?39=0
b%!40=0:b%!44=-eh%:b%!48=ew%:b%!52=0
b%!56=&0700013D:b%!60=&3000:b%!64=1:b%!68=mw%+(mh%<<16)
b%!72=ind%:b%!76=-1:b%!80=40:b%!84=0
SYS "Wimp_CreateWindow",,b% TO hd%
=hd%

REM The standard RISC OS program information window: labels on the left,
REM values in grey display fields with a sunken border (validation R2),
REM rows 52 OS units apart, as in the usual ProgInfo template
DEF PROCcreate_info
LOCAL i%, y%, l$, v$
info%=FNwindow_plain("About this program",612,268)
RESTORE +0
FOR i%=0 TO 4
  READ l$, v$
  IF i%=4 THEN v$=version$
  y%=-8-i%*52
  PROCicon(info%,8,y%-48,152,y%,&17000211,l$,"")
  PROCicon(info%,152,y%-48,602,y%,&1700013D,v$,"R2")
NEXT
ENDPROC
DATA Name:,NetStats
DATA Purpose:,Network statistics
DATA Author:,Andrew Youll
DATA Licence:,MIT (open source)
DATA Version:,-

DEF FNwindow_plain(t$, w%, h%)
LOCAL hh%, ind%
DIM ind% 40:$ind%=t$
b%!0=400:b%!4=600:b%!8=400+w%:b%!12=600+h%:b%!16=0:b%!20=0:b%!24=-1
b%!28=&84000012
b%?32=7:b%?33=2:b%?34=7:b%?35=1:b%?36=3:b%?37=2:b%?38=12:b%?39=0
b%!40=0:b%!44=-h%:b%!48=w%:b%!52=0
b%!56=&0700013D:b%!60=0:b%!64=1:b%!68=0
b%!72=ind%:b%!76=-1:b%!80=40:b%!84=0
SYS "Wimp_CreateWindow",,b% TO hh%
=hh%

DEF PROCicon(w%, x0%, y0%, x1%, y1%, fl%, t$, v$)
LOCAL ind%, val%
DIM ind% LEN(t$)+2:$ind%=t$
val%=-1
IF v$<>"" THEN DIM val% LEN(v$)+2:$val%=v$
b%!0=w%:b%!4=x0%:b%!8=y0%:b%!12=x1%:b%!16=y1%:b%!20=fl% OR &100
b%!24=ind%:b%!28=val%:b%!32=LEN(t$)+1
SYS "Wimp_CreateIcon",,b%
ENDPROC

REM Icon bar icon: the sprite, with the current rates written under it
REM ("v" = down, "^" = up) when "Rates on icon bar" is ticked
DEF PROCiconbar
DIM ibtext% 40, ibval% 16, isb% 40
$ibval%="S!netstats":$ibtext%="":ibtext$=""
ibw%=FNtextw("v8888Kb ^8888Kb")+16:IF ibw%<68 THEN ibw%=68
ibar%=-1
PROCiconbar_make
ENDPROC

REM create (or re-create next to the old one) in the current style
DEF PROCiconbar_make
LOCAL old%, w%
old%=ibar%
IF ibrates% THEN w%=ibw% ELSE w%=68
IF old%<0 THEN b%!0=-1 ELSE b%!0=-4
b%!4=0:b%!8=-16:b%!12=w%:b%!16=84
REM text + sprite, indirected, centred, click button type, fg 7 bg 1
b%!20=&1700310B
b%!24=ibtext%:b%!28=ibval%:b%!32=40
IF NOT ibrates% THEN $ibtext%="":ibtext$=""
SYS "Wimp_CreateIcon",old%,b% TO ibar%
IF old%>=0 THEN
  !isb%=-2:isb%!4=old%
  SYS "XWimp_DeleteIcon",,isb%
ENDIF
ENDPROC

REM short rate for the icon bar: 1023 B/s -> "1023B", 1.5 MB/s -> "1.5M"
DEF FNshort(r)
IF r<0 THEN r=0
IF bits% THEN
  r=r*8
  IF r<1000 THEN =STR$(INT(r+0.5))+"b"
  IF r<1E6 THEN =FNdp(r/1000)+"kb"
  IF r<1E9 THEN =FNdp(r/1E6)+"Mb"
  =FNdp(r/1E9)+"Gb"
ENDIF
IF r<1024 THEN =STR$(INT(r+0.5))+"B"
IF r<1048576 THEN =FNdp(r/1024)+"K"
IF r<1073741824 THEN =FNdp(r/1048576)+"M"
=FNdp(r/1073741824)+"G"

DEF PROCiconbar_text
LOCAL t$
IF NOT ibrates% THEN ENDPROC
IF stack%=0 THEN t$="offline" ELSE t$="v"+FNshort(totin)+" ^"+FNshort(totout)
IF t$=ibtext$ THEN ENDPROC
ibtext$=t$:$ibtext%=LEFT$(t$,38)
!isb%=-2:isb%!4=ibar%:isb%!8=0:isb%!12=0
SYS "XWimp_SetIconState",,isb%
ENDPROC

DEF FNwhich(h%)
LOCAL j%
FOR j%=0 TO NWIN%-1
  IF wh%(j%)=h% THEN =j%
NEXT
=-1

DEF PROCopen(j%)
!b%=wh%(j%)
SYS "Wimp_GetWindowState",,b%
REM first opening: put it back where it was last time (from Choices)
IF wposok%(j%) THEN
  b%!4=wpos%(j%,0):b%!8=wpos%(j%,1):b%!12=wpos%(j%,2):b%!16=wpos%(j%,3)
  wposok%(j%)=FALSE
ENDIF
b%!28=-1
SYS "Wimp_OpenWindow",,b%
wopen%(j%)=TRUE
PROCbuild_one(j%)
PROCset_extent(j%)
IF j%<>WMON% AND j%<>WCONN% THEN PROCrefresh_full(j%)
IF j%=WCONN% THEN PROCconnections
ENDPROC

DEF PROCclose(h%)
LOCAL j%
SYS "Wimp_CloseWindow",,b%
j%=FNwhich(h%):IF j%>=0 THEN wopen%(j%)=FALSE
ENDPROC

DEF PROCclosewin(j%)
!b%=wh%(j%)
SYS "Wimp_CloseWindow",,b%
wopen%(j%)=FALSE
ENDPROC

REM keep the work area extent in step with the number of lines
DEF PROCset_extent(j%)
LOCAL h%
IF j%=WMON% OR nlines%(j%)=lastn%(j%) THEN ENDPROC
lastn%(j%)=nlines%(j%)
h%=topm%+LH%*(nlines%(j%)+1):IF h%<700 THEN h%=700
b%!0=0:b%!4=-h%:b%!8=1400:b%!12=0
SYS "Wimp_SetExtent",wh%(j%),b%
ENDPROC

REM Update a window. Text windows only repaint the lines whose text
REM changed since the last update, so the rest doesn't flicker.
DEF PROCrefresh(j%)
LOCAL i%, i0%, n%
IF j%=WMON% OR nlines%(j%)<>pn%(j%) THEN PROCrefresh_full(j%):ENDPROC
n%=nlines%(j%):i%=0
WHILE i%<n%
  IF L$(j%,i%)<>P$(j%,i%) THEN
    i0%=i%
    WHILE i%<n% AND L$(j%,i%)<>P$(j%,i%)
      P$(j%,i%)=L$(j%,i%):i%+=1
    ENDWHILE
    PROCupdate_area(j%,-topm%-i%*LH%,-topm%-i0%*LH%)
  ELSE
    i%+=1
  ENDIF
ENDWHILE
ENDPROC

DEF PROCrefresh_full(j%)
LOCAL i%
PROCset_extent(j%)
IF j%<>WMON% THEN
  IF nlines%(j%)>0 THEN FOR i%=0 TO nlines%(j%)-1:P$(j%,i%)=L$(j%,i%):NEXT
  pn%(j%)=nlines%(j%)
ENDIF
PROCupdate_area(j%,-100000,100000)
ENDPROC

REM redraw part of a window's work area (y0 to y1, work area coordinates)
DEF PROCupdate_area(j%, y0%, y1%)
LOCAL more%
b%!0=wh%(j%):b%!4=-100000:b%!8=y0%:b%!12=100000:b%!16=y1%
SYS "Wimp_UpdateWindow",,b% TO more%
WHILE more%
  SYS "Wimp_SetColour",128+0:CLG
  PROCpaint(j%)
  SYS "Wimp_GetRectangle",,b% TO more%
ENDWHILE
ENDPROC

DEF PROCredraw(h%)
LOCAL more%, j%
j%=FNwhich(h%)
SYS "Wimp_RedrawWindow",,b% TO more%
WHILE more%
  IF j%>=0 THEN PROCpaint(j%)
  SYS "Wimp_GetRectangle",,b% TO more%
ENDWHILE
ENDPROC

DEF PROCpaint(j%)
IF j%=WMON% THEN PROCpaint_monitor ELSE PROCpaint_text(j%)
ENDPROC

DEF PROCtextcol(c%)
SYS "Wimp_TextOp",0,c%,&FFFFFF00
ENDPROC

DEF PROCtext(s$, x%, y%)
IF s$<>"" THEN SYS "Wimp_TextOp",2,s$,-1,-1,x%,y%
ENDPROC

DEF FNtextw(s$)
LOCAL w%
IF s$="" THEN =0
SYS "Wimp_TextOp",1,s$,0 TO w%
=w%

DEF PROCpaint_text(j%)
LOCAL ox%, oy%, i0%, i1%, i%, s$, c%, x%, y%, col%, t%, p%, q%, f$
ox%=b%!4-b%!20:oy%=b%!16-b%!24
i0%=(oy%-b%!40-topm%) DIV LH%-1:IF i0%<0 THEN i0%=0
i1%=(oy%-b%!32-topm%) DIV LH%+1:IF i1%>nlines%(j%)-1 THEN i1%=nlines%(j%)-1
IF i1%<i0% THEN ENDPROC
FOR i%=i0% TO i1%
  s$=L$(j%,i%):y%=oy%-topm%-(i%+1)*LH%+12
  col%=&00000000
  IF LEFT$(s$,1)="#" THEN col%=&A0400000:s$=MID$(s$,2)
  IF LEFT$(s$,1)="~" THEN col%=&70707000:s$=MID$(s$,2)
  IF LEFT$(s$,1)="!" THEN col%=&0000C000:s$=MID$(s$,2)
  PROCtextcol(col%)
  c%=0:p%=1
  REPEAT
    q%=INSTR(s$,CHR$9,p%)
    IF q%=0 THEN f$=MID$(s$,p%) ELSE f$=MID$(s$,p%,q%-p%)
    t%=tab%(j%,c%):IF c%>8 THEN t%=16
    IF t%>=0 THEN x%=ox%+t% ELSE x%=ox%-t%-FNtextw(f$)
    PROCtext(f$,x%,y%)
    c%+=1:p%=q%+1
  UNTIL q%=0 OR c%>8
NEXT
ENDPROC

REM ---------------------------------------------------------------------------
REM Monitor window: current rates and a scrolling graph
REM ---------------------------------------------------------------------------
DEF PROCpaint_monitor
LOCAL ox%, oy%, vw%, vh%, gx0%, gx1%, gy0%, gy1%, m, sc, i%, k%, x%, y%, px%, py%, step, s$, gh%
ox%=b%!4-b%!20:oy%=b%!16-b%!24
vw%=b%!12-b%!4:vh%=b%!16-b%!8
IF bits% THEN mul=8 ELSE mul=1
PROCtextcol(&00800000):PROCtext("Down  "+FNrate(totin),ox%+16,oy%-40)
PROCtextcol(&0000C000):PROCtext("Up  "+FNrate(totout),ox%+16+vw% DIV 2,oy%-40)
PROCtextcol(&70707000)
IF stack%=0 THEN
  s$="No Internet module loaded"
ELSE
  IF srcnote$<>"" THEN s$=srcnote$ ELSE s$=FNbytes(sumib)+" down, "+FNbytes(sumob)+" up since start-up"
  IF selif$<>"" AND srcnote$="" THEN s$=selif$+": "+s$
ENDIF
PROCtext(s$,ox%+16,oy%-80)
gx0%=ox%+16:gx1%=ox%+vw%-16:gy1%=oy%-104:gy0%=oy%-vh%+16
IF gy1%-gy0%<40 OR gx1%-gx0%<40 THEN ENDPROC
REM scale
m=0
IF hcount%>0 THEN
  FOR i%=0 TO hcount%-1
    k%=(hpos%-1-i%+2*HN%) MOD HN%
    IF hin(k%)>m THEN m=hin(k%)
    IF hout(k%)>m THEN m=hout(k%)
  NEXT
ENDIF
sc=FNnice(m)
REM frame and grid
SYS "ColourTrans_SetGCOL",&E0E0E000,,,0,0
FOR i%=1 TO 3
  y%=gy0%+(gy1%-gy0%)*i% DIV 4:MOVE gx0%,y%:DRAW gx1%,y%
NEXT
SYS "ColourTrans_SetGCOL",&90909000,,,0,0
MOVE gx0%,gy0%:DRAW gx1%,gy0%:DRAW gx1%,gy1%:DRAW gx0%,gy1%:DRAW gx0%,gy0%
PROCtextcol(&70707000):PROCtext(FNrate(sc/mul),gx0%+6,gy1%-30)
IF hcount%<2 THEN ENDPROC
gh%=gy1%-gy0%-2
step=(gx1%-gx0%-2)/(HN%-1)
REM download: filled area
SYS "ColourTrans_SetGCOL",&B0F0B000,,,0,0
px%=-1
FOR i%=hcount%-1 TO 0 STEP -1
  k%=(hpos%-1-i%+2*HN%) MOD HN%
  x%=gx1%-1-INT(i%*step):y%=gy0%+1+INT(gh%*FNclip(hin(k%)*mul/sc))
  IF px%>=0 THEN MOVE px%,gy0%+1:MOVE px%,py%:PLOT 85,x%,gy0%+1:PLOT 85,x%,y%
  px%=x%:py%=y%
NEXT
REM download line
SYS "ColourTrans_SetGCOL",&00800000,,,0,0
PROCplotline(hin(),gx0%,gx1%,gy0%,gh%,sc,step)
REM upload line
SYS "ColourTrans_SetGCOL",&0000C000,,,0,0
PROCplotline(hout(),gx0%,gx1%,gy0%,gh%,sc,step)
ENDPROC

DEF PROCplotline(h(), gx0%, gx1%, gy0%, gh%, sc, step)
LOCAL i%, k%, x%, y%, f%
f%=TRUE
FOR i%=hcount%-1 TO 0 STEP -1
  k%=(hpos%-1-i%+2*HN%) MOD HN%
  x%=gx1%-1-INT(i%*step):y%=gy0%+1+INT(gh%*FNclip(h(k%)*mul/sc))
  IF f% THEN MOVE x%,y%:f%=FALSE ELSE DRAW x%,y%
NEXT
ENDPROC

DEF FNclip(v)
IF v<0 THEN =0
IF v>1 THEN =1
=v

REM round the graph scale up to 1, 2 or 5 times a power of ten (in the
REM displayed unit: bits are counted in 1000s, bytes in 1024s)
DEF FNnice(m)
LOCAL u, p, f, n
IF bits% THEN m=m*8:u=1000 ELSE u=1024
IF m<u THEN m=u
p=1:WHILE m/p>=u:p=p*u:ENDWHILE
f=m/p:n=1
WHILE n<f
  IF n=1 OR n=10 OR n=100 THEN n=n*2 ELSE IF n=2 OR n=20 OR n=200 THEN n=n*5/2 ELSE n=n*2
ENDWHILE
=n*p

REM ===========================================================================
REM Connections: run ROD's inetstat (or netstat) and show what it says
REM ===========================================================================
REM The command runs in a TaskWindow, so the desktop keeps going and its
REM output comes back to us as TaskWindow_Output messages (no command window)
DEF PROCconnections
LOCAL cmd$, now%
IF connbusy% THEN
  REM give up on a run that has not finished in 30 seconds
  SYS "OS_ReadMonotonicTime" TO now%
  IF FNtdiff(now%,connstart%)<3000 THEN ENDPROC
  PROCtw_kill
ENDIF
cmd$=""
IF FNexists("Run:inetstat") THEN cmd$="inetstat -an"
IF cmd$="" AND FNexists("Run:netstat") THEN cmd$="netstat -an"
IF cmd$="" THEN
  nlines%(WCONN%)=0
  PROCaddl(WCONN%,"~No 'inetstat' command was found on Run$Path.")
  PROCaddl(WCONN%,"~The ROD stack installs it with its OpenBSD tools; once it is on")
  PROCaddl(WCONN%,"~the path, click in this window to look again.")
  SYS "OS_ReadMonotonicTime" TO connstamp%
  IF wopen%(WCONN%) THEN PROCrefresh_full(WCONN%)
  ENDPROC
ENDIF
conncmd$=cmd$:crn%=0:cpart$="":conntask%=0
SYS "XWimp_StartTask","TaskWindow """+cmd$+""" -wimpslot 2048K -name NetStats -quit -task &"+FNhex8(task%)+" -txt &"+FNhex8(conntxt%) TO ;f%
IF f% AND 1 THEN ENDPROC
connbusy%=TRUE
SYS "OS_ReadMonotonicTime" TO connstart%
IF nlines%(WCONN%)=0 THEN PROCaddl(WCONN%,"~Reading connections...")
IF wopen%(WCONN%) THEN PROCrefresh_full(WCONN%)
ENDPROC

REM TaskWindow messages: Ego (child started), Output (text), Morio (finished)
DEF PROCtw_message(rs%)
LOCAL n%, i%, c%, snd%
REM the PRM asks the parent to acknowledge each TaskWindow_Output
REM (the Wimp writes our handle into +4 when we send, so keep the sender)
snd%=b%!4
IF rs%=18 AND b%!16=&808C1 THEN b%!12=b%!8:SYS "XWimp_SendMessage",19,b%,snd%:b%!4=snd%
CASE b%!16 OF
  WHEN &808C2
    IF b%!20=conntxt% THEN conntask%=b%!4
  WHEN &808C1
    IF NOT connbusy% THEN ENDPROC
    IF conntask%=0 THEN conntask%=b%!4
    n%=b%!20:IF n%>232 THEN n%=232
    IF n%<=0 THEN ENDPROC
    FOR i%=0 TO n%-1
      c%=b%?(24+i%)
      IF c%=10 OR c%=13 THEN
        IF cpart$<>"" AND crn%<=MAXCR% THEN cr$(crn%)=cpart$:crn%+=1
        cpart$=""
      ELSE
        IF c%>=32 AND LEN(cpart$)<250 THEN cpart$+=CHR$c%
      ENDIF
    NEXT
  WHEN &808C3
    IF NOT connbusy% THEN ENDPROC
    IF cpart$<>"" AND crn%<=MAXCR% THEN cr$(crn%)=cpart$:crn%+=1
    cpart$="":connbusy%=FALSE:conntask%=0
    nlines%(WCONN%)=0
    PROCparse_conn(conncmd$)
    SYS "OS_ReadMonotonicTime" TO connstamp%
    IF wopen%(WCONN%) THEN PROCrefresh_full(WCONN%)
ENDCASE
ENDPROC

REM ask a running TaskWindow to stop (TaskWindow_Morite)
DEF PROCtw_kill
IF connbusy% AND conntask%<>0 THEN
  b%!0=20:b%!12=0:b%!16=&808C4
  SYS "XWimp_SendMessage",17,b%,conntask%
ENDIF
connbusy%=FALSE:conntask%=0
ENDPROC

DEF FNhex8(x%)=RIGHT$("0000000"+STR$~x%,8)

DEF FNexists(f$)
LOCAL t%, fl%
SYS "XOS_File",17,f$ TO t% ;fl%
IF fl% AND 1 THEN =FALSE
=(t%=1 OR t%=3)

DEF PROCparse_conn(cmd$)
LOCAL l$, n%, est%, lis%, ntcp%, nudp%, other%, T$, st$, i%, p$
T$=CHR$9
IF crn%=0 THEN PROCaddl(WCONN%,"!'"+cmd$+"' produced no output"):ENDPROC
PROCaddl(WCONN%,"")
PROCaddl(WCONN%,"#Proto"+T$+"Local address"+T$+"Remote address"+T$+"State"+T$+"Recv-Q"+T$+"Send-Q")
FOR i%=0 TO crn%-1
  l$=cr$(i%)
  n%=FNsplit(l$,cw$())
  IF n%>=5 THEN p$=FNlower(cw$(0)) ELSE p$=""
  IF LEFT$(p$,3)="tcp" OR LEFT$(p$,3)="udp" THEN
    st$="":IF n%>=6 THEN st$=cw$(5)
    PROCaddl(WCONN%,p$+T$+FNhostport(cw$(3))+T$+FNhostport(cw$(4))+T$+st$+T$+cw$(1)+T$+cw$(2))
    IF LEFT$(p$,3)="tcp" THEN
      ntcp%+=1
      IF st$="ESTABLISHED" THEN est%+=1
      IF st$="LISTEN" THEN lis%+=1
    ELSE
      nudp%+=1
    ENDIF
  ELSE
    IF l$<>"" AND INSTR(l$,"Proto")=0 AND INSTR(l$,"Active ")<>1 THEN
      other%+=1
      IF other%<=40 AND ntcp%+nudp%=0 THEN PROCaddl(WCONN%,"~"+LEFT$(l$,200))
    ENDIF
  ENDIF
NEXT
L$(WCONN%,0)="~"+STR$ntcp%+" TCP ("+STR$est%+" established, "+STR$lis%+" listening), "+STR$nudp%+" UDP.  Click to refresh."
ENDPROC

REM split on spaces; returns the number of words
DEF FNsplit(l$, w$())
LOCAL n%, p%, q%
n%=0:p%=1
WHILE p%<=LEN(l$) AND n%<=10
  WHILE MID$(l$,p%,1)=" " AND p%<=LEN(l$):p%+=1:ENDWHILE
  IF p%<=LEN(l$) THEN
    q%=INSTR(l$," ",p%):IF q%=0 THEN q%=LEN(l$)+1
    w$(n%)=MID$(l$,p%,q%-p%):n%+=1:p%=q%
  ENDIF
ENDWHILE
=n%

REM netstat prints host.port: show host:port instead
DEF FNhostport(a$)
LOCAL i%
IF a$="*.*" THEN ="*:*"
FOR i%=LEN(a$) TO 1 STEP -1
  IF MID$(a$,i%,1)="." THEN =LEFT$(a$,i%-1)+":"+MID$(a$,i%+1)
NEXT
=a$

REM ===========================================================================
REM Mouse and menus
REM ===========================================================================
DEF PROCclick
LOCAL w%, bt%, j%
w%=b%!12:bt%=b%!8
IF w%=-2 THEN
  IF bt%=2 THEN PROCshow_menu(b%!0-64,96+NMI%*44+3*24):ENDPROC
  IF bt%=4 THEN PROCopen(WMON%)
  IF bt%=1 THEN PROCopen(WIF%)
  ENDPROC
ENDIF
IF bt%=2 THEN PROCshow_menu(b%!0-64,b%!4):ENDPROC
j%=FNwhich(w%)
IF j%=WCONN% THEN PROCconnections
IF j%=WNET% THEN PROCbuild_one(WNET%):PROCrefresh_full(WNET%)
ENDPROC

DEF PROCcreate_menu
LOCAL i%, t$, fl%, tx%
NMI%=14
DIM menu% 28+24*NMI%, mtext%(NMI%)
$menu%="NetStats":menu%?12=7:menu%?13=2:menu%?14=7:menu%?15=0
menu%!16=25*16:menu%!20=44:menu%!24=0
RESTORE +0
FOR i%=0 TO NMI%-1
  READ t$, fl%
  DIM tx% 32:mtext%(i%)=tx%:$tx%=t$
  menu%!(28+i%*24)=fl%:menu%!(32+i%*24)=-1
  menu%!(36+i%*24)=&07000121
  menu%!(40+i%*24)=mtext%(i%):menu%!(44+i%*24)=-1:menu%!(48+i%*24)=32
NEXT
menu%!(28+(NMI%-1)*24)=menu%!(28+(NMI%-1)*24) OR &80
menu%!32=info%
REM the Interface submenu, filled in each time the menu opens
DIM ifmenu% 28+24*(MAXIF%+1), ifmtext%(MAXIF%+1)
$ifmenu%="Interface":ifmenu%?12=7:ifmenu%?13=2:ifmenu%?14=7:ifmenu%?15=0
ifmenu%!16=16*16:ifmenu%!20=44:ifmenu%!24=0
FOR i%=0 TO MAXIF%
  DIM tx% 24:ifmtext%(i%)=tx%:$tx%=""
  ifmenu%!(28+i%*24)=0:ifmenu%!(32+i%*24)=-1:ifmenu%!(36+i%*24)=&07000121
  ifmenu%!(40+i%*24)=tx%:ifmenu%!(44+i%*24)=-1:ifmenu%!(48+i%*24)=24
NEXT
menu%!(32+7*24)=ifmenu%
ENDPROC
DATA Info,0
DATA Monitor,0
DATA Interfaces,0
DATA Protocols,0
DATA Connections,0
DATA Data usage,0
DATA Network,2
DATA Interface,0
DATA Show bits/s,0
DATA Include loopback,0
DATA Rates on icon bar,0
DATA Auto-refresh connections,2
DATA Reset session totals,2
DATA Quit,0

REM "All interfaces" then one item per interface, the chosen one ticked
DEF PROCfill_ifmenu
LOCAL k%, f%
ifmname$(0)="":$ifmtext%(0)="All interfaces"
k%=1
WHILE k%<=ifn% AND k%<=MAXIF%
  ifmname$(k%)=ifname$(k%-1):$ifmtext%(k%)=LEFT$(ifname$(k%-1),20)
  k%+=1
ENDWHILE
FOR f%=0 TO k%-1
  ifmenu%!(28+f%*24)=0
  IF ifmname$(f%)=selif$ THEN ifmenu%!(28+f%*24)=1
  IF f%=0 THEN ifmenu%!(28+f%*24)=ifmenu%!(28+f%*24) OR 2
NEXT
ifmenu%!(28+(k%-1)*24)=ifmenu%!(28+(k%-1)*24) OR &80
ENDPROC

DEF PROCtick(i%, on%)
IF on% THEN menu%!(28+i%*24)=menu%!(28+i%*24) OR 1 ELSE menu%!(28+i%*24)=menu%!(28+i%*24) AND NOT 1
ENDPROC

DEF PROCshow_menu(x%, y%)
LOCAL j%
PROCtick(8,bits%):PROCtick(9,loopback%):PROCtick(10,ibrates%):PROCtick(11,autoconn%)
REM items 1-6 are the windows: tick the ones that are open
FOR j%=0 TO NWIN%-1:PROCtick(j%+1,wopen%(j%)):NEXT
PROCfill_ifmenu
mx%=x%:my%=y%
SYS "Wimp_CreateMenu",,menu%,x%,y%
ENDPROC

DEF PROCmenu_select
LOCAL i%
i%=!b%
SYS "Wimp_GetPointerInfo",,tmp%
CASE i% OF
  WHEN 1,2,3,4,5,6
    REM a ticked (open) window is closed again, an unticked one opened
    IF wopen%(i%-1) THEN PROCclosewin(i%-1) ELSE PROCopen(i%-1)
  WHEN 7
    IF b%!4>=0 AND b%!4<=MAXIF% THEN
      IF ifmname$(b%!4)<>selif$ THEN selif$=ifmname$(b%!4):hcount%=0:PROCtotals:PROCbuild_text:PROCrefresh_all:PROCiconbar_text
    ENDIF
  WHEN 8:bits%=NOT bits%:PROCbuild_text:PROCrefresh_all:PROCiconbar_text
  WHEN 9:loopback%=NOT loopback%:hcount%=0:PROCtotals:PROCrefresh_all:PROCiconbar_text
  WHEN 10:ibrates%=NOT ibrates%:PROCiconbar_make:PROCiconbar_text
  WHEN 11:autoconn%=NOT autoconn%
  WHEN 12:PROCsession_reset:IF wopen%(WUSE%) THEN PROCbuild_one(WUSE%):PROCrefresh(WUSE%)
  WHEN 13:quit%=TRUE
ENDCASE
IF NOT quit% THEN PROCsave_choices
IF (tmp%!8 AND 1) AND NOT quit% THEN PROCshow_menu(mx%,my%)
ENDPROC

REM ===========================================================================
REM Data usage: bytes counted while NetStats runs, per day and this session.
REM Saved in <Choices$Write>.NetStats.Usage as "YYYY-MM-DD down up" lines.
REM ===========================================================================
DEF PROCusage_add(dt)
LOCAL j%, din, dout
IF stack%=0 THEN ENDPROC
IF ifok% THEN
  j%=0
  WHILE j%<ifn%
    IF (ifflags%(j%) AND iffloop%)=0 THEN din+=rin(j%)*dt:dout+=rout(j%)*dt
    j%+=1
  ENDWHILE
ELSE
  IF tcpok% THEN din=st_rate(tcp_rcvbyte%)*dt:dout=st_rate(tcp_sndbyte%)*dt
ENDIF
sessin+=din:sessout+=dout
PROCusage_day(FNdate_of(TIME$),din,dout)
ENDPROC

REM add to the entry for day d$ (the last entry, or a new one)
DEF PROCusage_day(d$, din, dout)
LOCAL i%
IF un%=0 THEN
  un%=1:udate$(0)=d$:udin(0)=0:udout(0)=0
ELSE
  IF udate$(un%-1)<>d$ THEN
    IF un%>MAXDAYS% THEN
      FOR i%=1 TO un%-1:udate$(i%-1)=udate$(i%):udin(i%-1)=udin(i%):udout(i%-1)=udout(i%):NEXT
      un%-=1
    ENDIF
    udate$(un%)=d$:udin(un%)=0:udout(un%)=0:un%+=1
  ENDIF
ENDIF
udin(un%-1)+=din:udout(un%-1)+=dout
ENDPROC

REM "Sun,04 Oct 2026.12:34:56" -> "2026-10-04"
DEF FNdate_of(t$)
LOCAL m%
m%=(INSTR("JanFebMarAprMayJunJulAugSepOctNovDec",MID$(t$,8,3))+2) DIV 3
=MID$(t$,12,4)+"-"+RIGHT$("0"+STR$m%,2)+"-"+MID$(t$,5,2)

DEF PROCsession_reset
sessin=0:sessout=0:sessstart$=MID$(TIME$,17,5)+" "+MID$(TIME$,5,6)
ENDPROC

REM whole number as plain digits (no commas, no exponent)
DEF FNplain(x)
LOCAL s$, i%, r$
s$=FNnum(x)
FOR i%=1 TO LEN(s$)
  IF MID$(s$,i%,1)<>"," THEN r$+=MID$(s$,i%,1)
NEXT
=r$

DEF PROCload_usage
LOCAL h%, f%, l$
un%=0
SYS "XOS_Find",&4F,"Choices:NetStats.Usage" TO h% ;f%
IF (f% AND 1) OR h%=0 THEN ENDPROC
WHILE NOT EOF#h%
  l$=GET$#h%
  IF FNsplit(l$,cw$())=3 AND LEN(cw$(0))=10 THEN
    IF MID$(cw$(0),5,1)="-" THEN PROCusage_day(cw$(0),VAL(cw$(1)),VAL(cw$(2)))
  ENDIF
ENDWHILE
CLOSE#h%
ENDPROC

DEF PROCsave_usage
LOCAL h%, f%, j%, d$
IF un%=0 THEN ENDPROC
d$="<Choices$Write>.NetStats"
SYS "XOS_ReadVarVal","Choices$Write",tmp%,-1,0,0 TO ,,j% ;f%
IF j%=0 THEN ENDPROC
SYS "XOS_File",8,d$,0 TO ;f%
SYS "XOS_Find",&8F,d$+".Usage" TO h% ;f%
IF (f% AND 1) OR h%=0 THEN ENDPROC
FOR j%=0 TO un%-1
  BPUT#h%,udate$(j%)+" "+FNplain(udin(j%))+" "+FNplain(udout(j%))
NEXT
CLOSE#h%
SYS "XOS_File",18,d$+".Usage",&FFF
ENDPROC

DEF PROCtext_usage
LOCAL T$, i%, k%, today$, m$, mi, mo, n%
T$=CHR$9
nlines%(WUSE%)=0
PROCaddl(WUSE%,"~Counted while NetStats is running; loopback (lo0) is not included.")
PROCaddl(WUSE%,"#"+T$+"Down"+T$+"Up"+T$+"Total")
PROCaddl(WUSE%,FNuse_row("This session (since "+sessstart$+")",sessin,sessout))
today$=FNdate_of(TIME$)
IF un%>0 THEN
  IF udate$(un%-1)=today$ THEN PROCaddl(WUSE%,FNuse_row("Today",udin(un%-1),udout(un%-1)))
ENDIF
m$=LEFT$(today$,7):mi=0:mo=0
FOR i%=0 TO un%-1
  IF LEFT$(udate$(i%),7)=m$ THEN mi+=udin(i%):mo+=udout(i%)
NEXT
PROCaddl(WUSE%,FNuse_row("This month",mi,mo))
IF un%=0 THEN ENDPROC
PROCaddl(WUSE%,"")
PROCaddl(WUSE%,"#Last 14 days"+T$+"Down"+T$+"Up"+T$+"Total")
FOR i%=un%-1 TO un%-14 STEP -1
  IF i%>=0 THEN PROCaddl(WUSE%,FNuse_row(udate$(i%),udin(i%),udout(i%)))
NEXT
PROCaddl(WUSE%,"")
PROCaddl(WUSE%,"#Last 12 months"+T$+"Down"+T$+"Up"+T$+"Total")
i%=un%-1:n%=0
WHILE i%>=0 AND n%<12
  m$=LEFT$(udate$(i%),7):mi=0:mo=0:k%=TRUE
  WHILE k%
    mi+=udin(i%):mo+=udout(i%):i%-=1
    IF i%<0 THEN k%=FALSE ELSE IF LEFT$(udate$(i%),7)<>m$ THEN k%=FALSE
  ENDWHILE
  PROCaddl(WUSE%,FNuse_row(m$,mi,mo)):n%+=1
ENDWHILE
ENDPROC

DEF FNuse_row(l$, a, b)=l$+CHR$9+FNbytes(a)+CHR$9+FNbytes(b)+CHR$9+FNbytes(a+b)

REM ===========================================================================
REM Network: host name, DNS, gateways and the routing table
REM (net.route.0.0.dump, RTM_GET messages)
REM ===========================================================================
DEF PROCread_routes
LOCAL n%
rtn%=0:gw4$="":gw6$="":rterr$=""
IF stack%=0 THEN ENDPROC
PROCmib(CTL_NET%,PF_ROUTE%,0,0,NET_RT_DUMP%,0)
n%=FNsysctl(mib%,6,rtbuf%,32768)
IF n%<0 THEN rterr$=sysctl_err$:ENDPROC
PROCparse_routes(rtbuf%,n%)
ENDPROC

DEF PROCparse_routes(buf%, n%)
LOCAL p%, ml%, hdr%, idx%, addrs%, fl%, sa%, bit%, l%, dst%, gw%, nm%, d$, g$, f$, i$, fam%, skip%
p%=buf%
WHILE p%+4<=buf%+n% AND rtn%<MAXRT%
  ml%=FNu16(p%)
  REM a broken length ends the walk
  IF ml%<4 THEN ml%=buf%+n%-p%+4:p%?3=0
  IF p%?3=4 THEN
    IF stack%=2 THEN
      hdr%=FNu16(p%+4):idx%=FNu16(p%+6):addrs%=p%!12:fl%=p%!16:skip%=&600600
    ELSE
      hdr%=92:idx%=FNu16(p%+4):fl%=p%!8:addrs%=p%!12:skip%=&E00400
    ENDIF
    REM leave out ARP/ND, local, broadcast and multicast entries
    IF (fl% AND skip%)=0 THEN
      dst%=0:gw%=0:nm%=0:sa%=p%+hdr%
      FOR bit%=0 TO 7
        IF addrs% AND (1<<bit%) THEN
          IF bit%=0 THEN dst%=sa%
          IF bit%=1 THEN gw%=sa%
          IF bit%=2 THEN nm%=sa%
          l%=?sa%:IF l%=0 THEN sa%+=4 ELSE sa%+=((l%-1) OR 3)+1
        ENDIF
      NEXT
      IF dst% THEN PROCadd_route(dst%,gw%,nm%,fl%,idx%)
    ENDIF
  ENDIF
  p%+=ml%
ENDWHILE
ENDPROC

DEF PROCadd_route(dst%, gw%, nm%, fl%, idx%)
LOCAL fam%, d$, g$, f$, i$, T$, j%, pb%
T$=CHR$9:fam%=dst%?1
IF fam%=AF_INET% THEN
  d$=FNip4(dst%+4)
  IF fl% AND 4 THEN pb%=32 ELSE IF nm% THEN pb%=FNmaskbits(nm%,4,4) ELSE pb%=-1
  IF d$="0.0.0.0" AND pb%<=0 THEN d$="default" ELSE IF pb%>=0 AND pb%<32 THEN d$+="/"+STR$pb%
ELSE
  IF fam%<>24 AND fam%<>28 THEN ENDPROC
  d$=FNip6(dst%+8,"")
  IF fl% AND 4 THEN pb%=128 ELSE IF nm% THEN pb%=FNmaskbits(nm%,8,16) ELSE pb%=-1
  IF d$="::" AND pb%<=0 THEN d$="default" ELSE IF pb%>=0 AND pb%<128 THEN d$+="/"+STR$pb%
ENDIF
g$=FNsa_text(gw%)
f$="":IF fl% AND 1 THEN f$+="U"
IF fl% AND 2 THEN f$+="G"
IF fl% AND 4 THEN f$+="H"
IF fl% AND &800 THEN f$+="S"
IF fl% AND &10 THEN f$+="D"
j%=FNfind(idx%):IF j%>=0 THEN i$=ifname$(j%) ELSE i$="if"+STR$idx%
IF d$="default" AND (fl% AND 2) THEN
  IF fam%=AF_INET% THEN gw4$=g$+" ("+i$+")" ELSE gw6$=g$+" ("+i$+")"
ENDIF
IF d$="default" AND fam%<>AF_INET% THEN d$="default (IPv6)"
IF LEN(d$)>22 THEN
  rt$(rtn%)=d$:rtn%+=1
  IF rtn%<MAXRT% THEN rt$(rtn%)=T$+T$+g$+T$+f$+T$+i$:rtn%+=1
ELSE
  rt$(rtn%)=d$+T$+T$+g$+T$+f$+T$+i$:rtn%+=1
ENDIF
ENDPROC

REM a gateway sockaddr as text: an address, or the interface for direct routes
DEF FNsa_text(sa%)
LOCAL fam%, j%
IF sa%=0 THEN =""
fam%=sa%?1
IF fam%=AF_INET% THEN =FNip4(sa%+4)
IF fam%=24 OR fam%=28 THEN =FNip6(sa%+8,"")
IF fam%=AF_LINK% THEN
  j%=FNfind(FNu16(sa%+2))
  IF j%>=0 THEN ="direct ("+ifname$(j%)+")"
  ="direct"
ENDIF
=""

REM read a system variable (own buffer: tmp% holds the pointer info in
REM PROCmenu_select while windows are rebuilt)
DEF FNvar(n$)
LOCAL f%, l%
SYS "XOS_ReadVarVal",n$,vbuf%,250,0,3 TO ,,l% ;f%
IF f% AND 1 THEN =""
vbuf%?l%=13
=LEFT$($vbuf%,200)

DEF PROCtext_net
LOCAL T$, i%, v$
T$=CHR$9
nlines%(WNET%)=0
PROCaddl(WNET%,"~Click in this window to refresh. Settings come from the Inet$ system variables.")
PROCaddl(WNET%,"#This machine")
v$=FNvar("Inet$HostName"):IF v$="" THEN v$="(not set)"
PROCaddl(WNET%,"Host name"+T$+v$)
v$=FNvar("Inet$LocalDomain"):IF v$<>"" THEN PROCaddl(WNET%,"Domain"+T$+v$)
v$=FNvar("Inet$Resolvers"):IF v$="" THEN v$="(none set)"
PROCaddl(WNET%,"DNS servers"+T$+v$)
IF gw4$<>"" THEN PROCaddl(WNET%,"Gateway"+T$+gw4$) ELSE PROCaddl(WNET%,"Gateway"+T$+"(no default route)")
IF gw6$<>"" THEN PROCaddl(WNET%,"IPv6 gateway"+T$+gw6$)
PROCaddl(WNET%,"")
IF rterr$<>"" THEN PROCaddl(WNET%,"~Routing table not available: "+rterr$):ENDPROC
PROCaddl(WNET%,"#Destination"+T$+T$+"Gateway"+T$+"Flags"+T$+"Interface")
IF rtn%=0 THEN PROCaddl(WNET%,"~No routes"):ENDPROC
FOR i%=0 TO rtn%-1:PROCaddl(WNET%,rt$(i%)):NEXT
PROCaddl(WNET%,"")
PROCaddl(WNET%,"~Flags: U up, G via a gateway, H host, S static, D dynamic (redirect)")
ENDPROC

REM ===========================================================================
REM Choices: <Choices$Write>.NetStats.Choices, read via Choices:
REM   lines "name value", e.g. "bits 1", "window 2 1 x0 y0 x1 y1"
REM ===========================================================================
DEF PROCload_choices
LOCAL h%, f%, l$, k$, a$, j%, i%, p%
SYS "XOS_Find",&4F,"Choices:NetStats.Choices" TO h% ;f%
IF (f% AND 1) OR h%=0 THEN ENDPROC
WHILE NOT EOF#h%
  l$=GET$#h%
  p%=INSTR(l$," ")
  IF p%>0 THEN
    k$=LEFT$(l$,p%-1):a$=MID$(l$,p%+1)
    CASE k$ OF
      WHEN "bits":bits%=(VAL(a$)<>0)
      WHEN "loopback":loopback%=(VAL(a$)<>0)
      WHEN "iconbar":ibrates%=(VAL(a$)<>0)
      WHEN "autoconn":autoconn%=(VAL(a$)<>0)
      WHEN "interface":selif$=LEFT$(a$,16)
      WHEN "window"
        IF FNsplit(a$,cw$())>=6 THEN
          j%=VAL(cw$(0))
          IF j%>=0 AND j%<NWIN% THEN
            wwasopen%(j%)=(VAL(cw$(1))<>0)
            FOR i%=0 TO 3:wpos%(j%,i%)=VAL(cw$(2+i%)):NEXT
            wposok%(j%)=(wpos%(j%,2)-wpos%(j%,0)>=64 AND wpos%(j%,3)-wpos%(j%,1)>=64)
          ENDIF
        ENDIF
    ENDCASE
  ENDIF
ENDWHILE
CLOSE#h%
ENDPROC

DEF PROCsave_choices
LOCAL h%, f%, j%, d$
d$="<Choices$Write>.NetStats"
SYS "XOS_ReadVarVal","Choices$Write",tmp%,-1,0,0 TO ,,j% ;f%
IF j%=0 THEN ENDPROC
SYS "XOS_File",8,d$,0 TO ;f%
SYS "XOS_Find",&8F,d$+".Choices" TO h% ;f%
IF (f% AND 1) OR h%=0 THEN ENDPROC
BPUT#h%,"# NetStats choices"
BPUT#h%,"bits "+STR$(-bits%)
BPUT#h%,"loopback "+STR$(-loopback%)
BPUT#h%,"iconbar "+STR$(-ibrates%)
BPUT#h%,"autoconn "+STR$(-autoconn%)
IF selif$<>"" THEN BPUT#h%,"interface "+selif$
FOR j%=0 TO NWIN%-1
  !b%=wh%(j%)
  SYS "XWimp_GetWindowState",,b% TO ;f%
  IF (f% AND 1)=0 THEN BPUT#h%,"window "+STR$j%+" "+STR$(-wopen%(j%))+" "+STR$(b%!4)+" "+STR$(b%!8)+" "+STR$(b%!12)+" "+STR$(b%!16)
NEXT
CLOSE#h%
SYS "XOS_File",18,d$+".Choices",&FFF
ENDPROC

DEF PROCrefresh_all
LOCAL j%
FOR j%=0 TO NWIN%-1
  IF wopen%(j%) THEN PROCrefresh_full(j%)
NEXT
ENDPROC
