#
# p0f - passive OS fingerprinting
# -------------------------------
# (C) Copyright 2000, 2001 by Michal Zalewski <lcamtuf@coredump.cx>
# (C) Copyright 2001 by William Stearns <wstearns@pobox.com>
#
# Every entry in this file is a description of unique TCP parameters 
# specific for the first SYN packet sent by a remote party while 
# establishing a connection. Those parameters include: window size (wss),
# maximum segment size (mss), don't fragment flag (DF), window scaling 
# (wscale), sackOK flag, nop flag, initial time to live (TTL) and SYN
# packet size (as declared).
#
# Normally, p0f reports unknown OSes providing you with all parameters,
# so you can simply find out what system your party runs, and then,
# add appropriate rule to this file. There's only thing you have to do
# - determine initial TTL of a packet. Well, usually it is equal to the first
# power of 2 greater than TTL you're seeing, given that your remote party is
# not too far away (if traceroute shows more than 20-25 hosts, be careful).
# So, for example, if you get TTL of 55 in a fingerprint returned by p0f,
# initial TTL probably was 64. NOTE: it is better to overestimate it (will
# affect distance prediction) than to underestimate (will not work at all in
# some cases).
#
# There are some brain-damaged devices, like network printers, that
# have initial TTLs set to values like 60. However, if you see HP LaserJet
# trying to connect your server, you probably should have a break :)
#
# Format:
#
# wwww:ttt:mmm:D:W:S:N:I:OS Description
#
# wwww - window size
# ttt  - time to live
# mmm  - maximum segment size
# D    - don't fragment flag  (0=unset, 1=set) 
# W    - window scaling (-1=not present, other=value)
# S    - sackOK flag (0=unset, 1=set)
# N    - nop flag (0=unset, 1=set)
# I    - packet size (-1 = irrevelant)
#

31072:64:3884:1:0:1:1:-1:Linux 2.2.12-20 (RH 6.1)
512:64:1460:0:0:0:0:44:Linux 2.0.35 - 2.0.38
32120:64:1460:1:0:1:1:60:Linux 2.2.9 - 2.2.18
16384:64:1460:1:0:0:0:44:FreeBSD 4.0-STABLE, 3.2-RELEASE
8760:64:1460:1:0:0:0:-1:Solaris 2.6 (2)
9140:255:9140:1:0:0:0:-1:Solaris 2.6 (sunsite)
49152:64:1460:0:0:0:0:44:IRIX 6.5 / 6.4
8760:255:1460:1:0:0:0:44:Solaris 2.6 or 2.7 (1)
8192:128:1460:1:0:0:0:44:Windows NT 4.0 (1)
8192:128:1460:1:0:1:1:48:Windows 9x (1)
8192:128:536:1:0:1:1:48:Windows 9x (2)
2144:64:536:1:0:1:1:60:Windows 9x (4)
16384:128:1460:1:0:1:1:48:Windows 2000 (1)
32120:32:1460:1:0:1:1:60:Linux 2.2.13 (1)
8192:32:1460:1:0:0:0:44:Windows NT 4.0 (2)
5840:128:536:1:0:1:1:48:Windows 95 (3)
16060:64:1460:1:0:1:1:60:Debian/Caldera Linux 2.2.x (check)
8760:255:1380:1:0:0:0:44:Solaris 2.7
8192:128:1456:1:0:1:1:64:Linux 2.2.13 (2)
32768:64:1432:0:0:0:0:44:PlusGSM, InterNetia proxy ???
16384:255:1460:1:0:0:1:48:FreeBSD 2.2.6-RELEASE
8192:64:1460:1:0:0:1:60:BSDI BSD/OS 3.1 - 4.0
16384:64:1460:0:0:0:1:60:NetBSD 1.3/i386
24820:64:1460:1:0:0:0:44:SCO UnixWare 7.0.1, Win 9x
32768:64:1460:1:0:0:0:44:HP-UX B.10.01 A 9000/712
16384:64:512:0:0:0:0:44:AIX 3.2, 4.2 - 4.3
32768:64:1460:1:0:0:1:48:Digital UNIX V4.0E, Mac OS X
32694:255:536:0:0:0:0:-1:3Com HiPer ARC, System V4.2.32
4128:255:556:0:0:0:0:-1:Cisco IOS 1750/12.0(5), 2500/11.3(1), 3600/12.0(7)
4288:255:1460:0:-1:0:0:-1:Cisco IOS 3620/11.2(17)P
512:64:0:0:-1:0:0:-1:Linux 2.0.35 - 2.0.37
8192:128:1460:1:-1:1:0:44:Windows NT 
32120:64:1460:1:190:1:1:60:Linux 2.2.16
32696:64:536:0:0:1:1:60:SCO UnixWare 7.1.0 x86 (1)
24820:64:1460:1:0:0:1:60:SCO UnixWare 7.1.0 x86 (2), Linux 2.4.0
24820:64:1460:1:0:0:1:48:SCO UnixWare 7.1.0 x86 ? (3)
32120:64:1460:0:-1:0:0:44:Linux 2.0.38 (2)
65535:128:1368:1:-1:0:0:44:BorderManager 3.0 - 3.5, Windows 98, Windows NT 5.0
33580:255:1460:1:-1:0:0:44:Solaris 7
8192:128:25443:1:-1:1:1:-1:Microsoft NT 4.0 Server SP5
8192:64:1460:1:-1:0:0:44:AXCENT Raptor Firewall Windows NT 4.0/SP3
8192:32:1456:1:-1:0:0:44:Windows 95 (4)
16384:64:0:0:-1:0:0:-1:ULTRIX V4.5 (Rev. 47)
16384:64:512:0:0:0:1:60:OpenBSD 2.6-2.8
32768:128:1460:1:-1:0:0:-1:Novell NetWare 4.11
16384:64:1460:1:0:0:1:44:FreeBSD 2.2.8-RELEASE
4288:255:536:0:-1:0:0:-1:Cisco IOS 1600/11.2(15)P, 2500/11.2(5)P, 4500/11.1(7)
4096:32:1024:0:245:0:0:-1:Alcatel (Xylan) OmniStack 5024
2144:255:536:0:-1:0:0:-1:Cisco IGS 3000 IOS 11.x(16), 2500 IOS 11.2(3)P
4128:255:1460:0:-1:0:0:-1:Cisco IOS 2611/11.3(2)XA4, C2600/12.0(5)T1, 4500/12.0(9), 3640/12.1(2), 3620/12.0(8) or 11.3(11a)
61440:64:1460:0:-1:0:0:44:IRIX 6.3
61440:64:512:0:-1:0:0:-1:IRIX 5.3 / 4.0.5F
31856:64:1460:1:0:1:1:60:Linux 2.3.99-ac - 2.4.0-test1
4096:32:1024:0:245:0:0:-1:Alcatel (Xylan) OmniStack 5024 v3.4.5
4096:32:1024:0:-1:0:0:-1:Chorus MiX V.3.2 r4.1.5 COMP-386
32120:64:1460:1:101:1:1:60:Linux 2.2.15
32120:64:1460:0:-1:0:0:-1:Linux 2.0.33 (1)
512:64:1460:0:52:0:0:44:Linux 2.0.33 (2)
32120:64:1460:0:0:1:1:60:Linux 2.2.19
5840:64:1460:1:0:1:1:60:Linux 2.4.2 - 2.4.14 (1)
32768:255:1460:1:0:0:1:48:Mac OS 9 (1)
65535:255:1460:1:1:0:1:48:Mac OS 9 (2)
24820:64:1460:1:-1:1:1:48:SunOS 5.8
32768:32:1460:1:-1:0:0:44:Windows CE 3.0 (Ipaq 3670) (1)
32768:32:1460:1:-1:0:1:44:Windows CE 3.0 (Ipaq 3670) (2)
24820:64:1460:1:-1:1:1:-1:SunOS 5.8 Sparc
12288:255:1460:0:-1:0:0:44:BeOS 5.0 (1)
12288:255:1460:0:-1:0:1:44:BeOS 5.0 (2)
32768:128:1460:1:0:0:1:48:Dec V4.0 OSF1
16384:64:1460:0:-1:0:0:44:AIX 4.3 - 4.3.3, Windows 98
61440:64:1460:0:-1:1:1:48:IRIX 6.5.10
5840:64:1460:1:0:1:1:52:Linux 2.4.1-14 (1)
44032:128:64059:1:-1:1:1:-1:Windows 2000 SP2 (1)
44032:128:1452:1:-1:1:1:48:Windows 2000 SP2 (2)
16384:128:25275:1:-1:1:1:-1:Windows 2000 (2)
1024:64:0:0:-1:0:0:40:NMAP scan (distance inaccurate) (1)
1024:64:265:0:10:0:1:60:NMAP scan (distance inaccurate) (2)
1024:64:536:0:-1:0:0:40:NMAP scan (distance inaccurate) (3)
3072:64:0:0:-1:0:0:40:NMAP scan (distance inaccurate) (4)
3072:64:265:0:10:0:1:60:NMAP scan (distance inaccurate) (5)
3072:64:536:0:-1:0:0:40:NMAP scan (distance inaccurate) (6)
2048:64:0:0:-1:0:0:40:NMAP scan (distance inaccurate) (7)
2048:64:265:0:10:0:1:60:NMAP scan (distance inaccurate) (8)
2048:64:536:0:-1:0:0:40:NMAP scan (distance inaccurate) (9)
4096:64:0:0:-1:0:0:40:NMAP scan (distance inaccurate) (10)
4096:64:265:0:10:0:1:60:NMAP scan (distance inaccurate) (11)
4096:64:536:0:-1:0:0:40:NMAP scan (distance inaccurate) (12)
16384:64:1460:1:94:0:1:44:FreeBSD 4.0-STABLE, 3.2-RELEASE (2)
16384:64:1460:1:98:0:0:44:FreeBSD 4.0-STABLE, 3.2-RELEASE (3)
16384:64:1460:1:112:0:0:44:FreeBSD 4.0-STABLE, 3.2-RELEASE (4)
16384:64:1460:1:0:0:1:60:Linux 2.4.2 - 2.4.14 (2)
8760:255:1460:1:-1:0:1:44:Solaris 2.6 or 2.7 (2)
8192:128:1460:1:0:1:1:64:Windows 9x (5)
8192:128:1460:1:0:1:1:44:Windows 9x (6)
5840:64:1460:1:0:1:1:48:Linux 2.4.1-14 (2)
5840:64:1460:1:0:0:1:60:Linux 2.4.13-ac7
4660:255:0:0:-1:0:0:40:Queso 1.2 (OS unknown, Linux, Solaris, *BSD, others?)
64240:128:1460:1:-1:1:1:48:Windows XP Pro, Windows 2000 Pro
16384:128:1440:1:-1:1:1:48:Windows XP Pro
32696:64:536:1:0:1:1:60:Anonymizer.com proxy (Unixware?)
8192:64:1460:1:0:1:1:64:WebTV netcache engine (BSDI)
65535:64:1460:0:1:0:1:48:AOL proxy, Compaq Tru64 UNIX V5.1 (Rev. 732)
32320:64:1616:1:0:1:1:60:Linux (unknown?) (1)
5840:64:1460:0:0:1:1:60:Linux (unknown?) (2)
5840:128:1460:1:-1:1:1:48:Windows 95 or early NT4
8192:128:536:1:-1:1:1:48:Windows 9x or 2000
5808:64:1452:1:0:1:1:60:Linux 2.4.10 (1)
5808:64:1452:1:111:1:1:60:Linux 2.4.10 (2)
16384:128:1460:1:75:1:1:48:Windows ME
15972:64:1452:1:0:1:1:60:Windows 98 (?)
16384:128:1452:1:-1:1:1:48:Windows 2000 (4)
16384:128:1360:1:-1:1:1:48:Windows 2000 (5)
8192:128:1460:0:-1:1:1:48:Windows 95 (?) (6)
8192:128:1414:1:-1:1:1:48:Windows 9x or NT4
8760:128:536:1:-1:1:1:48:Windows 2000 Pro (2128)
64240:255:1460:1:-1:0:0:44:Linux 2.1.xx (?)
16384:128:1414:1:-1:1:1:48:Windows 2000 (8)
8192:128:1360:1:-1:1:1:48:Windows 9x (9)
65535:64:1460:0:0:0:1:60:CacheOS 3.1 on a CacheFlow 6000
31944:64:1412:1:0:1:1:60:Linux 2.2
16384:128:1460:1:-1:1:1:48:Windows 2000 (9)
8192:64:1460:0:-1:0:0:44:CacheFlow 500x CacheOS 2.1.08 - 2.2.1
5535:64:1460:1:0:0:1:60:FreeBSD 2.2.1 - 4.1
512:64:1460:0:-1:0:0:44:Linux 2.0.34-38
65535:64:1432:0:-1:0:0:44:Cisco webcache
16384:128:55370:1:-1:1:1:48:early Windows 2000
2144:64:536:1:0:1:1:48:Windows 9x (10)
8192:64:1460:1:0:1:1:60:BSDI BSD/OS 3.0 - 4.0 (or MacOS, NetBSD)
16384:64:1460:1:0:0:1:68:FreeBSD 4.3 - 4.4PRERELEASE
8760:255:1460:1:-1:1:0:44:Solaris 2.6 - 2.7
32120:64:1460:1:9:1:1:60:Linux 2.2.x
4288:128:1460:1:-1:1:1:48:Windows NT SP3 (1)
8192:128:1456:1:-1:1:1:48:Windows NT SP3 (2)
16384:64:572:1:0:1:1:64:OpenBSD 3.0
63903:128:0:0:-1:0:0:40:Linux 2.2.x or 2.4.x
16384:128:1272:1:-1:1:1:48:Windows NT SP3 (3)
16616:255:1460:1:0:0:0:48:Mac OS 7.x-9.x
16384:128:572:1:-1:1:1:48:Windows NT SP4+
32768:64:1460:1:0:0:1:60:Mac OS X 10.1
32768:64:1460:1:122:0:1:60:Mac OS X 10.1 (2)
32120:64:1460:1:100:1:1:60:Linux 2.2.14
65535:128:1372:1:-1:1:1:48:Windows 98 (2)
5840:64:1460:1:223:1:1:60:Linux-2.4.13-ac7
8192:128:1460:1:52:1:1:48:Windows 98 (3)
65535:128:1460:1:-1:1:1:48:Windows 98 (4)
16384:128:1460:1:52:1:1:48:Windows NT 5.0 (1)
8760:128:1460:1:-1:1:1:48:Windows NT 5.0 (2)
60352:64:1360:1:2:1:1:52:Windows NT 5.0 (3)
11400:64:3800:1:0:1:1:60:Linux 2.4.0-0.99.11 Redhat 7.0 Beta (Fischer)
32767:64:16396:1:0:1:1:60:Linux 2.4.20
32768:255:1380:1:-1:0:1:48:Macintosh PPC (1)
32768:255:1436:1:0:0:1:48:Macintosh PPC (2)
32768:255:1443:1:0:0:1:48:Macintosh PPC (3)
32768:255:1452:1:0:0:1:48:Macintosh PPC (4)
32768:255:1460:0:0:0:1:48:Macintosh PPC (5)
32768:255:1460:1:0:1:1:48:Macintosh PPC (6)
32768:64:10:1:0:0:1:60:Macintosh PPC (7)
32768:64:1322:1:0:0:1:60:Macintosh PPC (8)
32768:64:1360:1:0:0:1:60:Macintosh PPC (9)
32768:64:1380:1:-1:0:1:60:Macintosh PPC (10)
32768:64:1380:1:0:0:1:60:Macintosh PPC (11)
32768:64:1400:1:0:0:1:60:Macintosh PPC (12)
32768:64:1400:1:64:0:1:60:Macintosh PPC (13)
32768:64:1414:1:0:0:1:60:Macintosh PPC (14)
32768:64:1420:1:0:0:1:60:Macintosh PPC (15)
32768:64:1422:1:0:0:1:60:Macintosh PPC (16)
32768:64:1452:1:0:0:1:60:Macintosh PPC (17)
32768:64:1460:1:0:1:1:60:Macintosh PPC Mac OS X
32768:64:1460:1:143:0:1:60:Macintosh PPC (18)
32768:64:1460:1:153:0:1:60:Macintosh PPC (19)
32768:64:1460:1:37:0:1:60:Macintosh PPC (20)
32768:64:2560:1:0:0:1:60:Macintosh PPC (21)
32768:64:58045:1:0:0:1:60:Macintosh PPC (22)
32768:255:0:1:0:0:1:48:Macintosh PPC (23)
32768:255:1360:1:0:0:1:48:Macintosh PPC (24)
32768:255:1380:1:0:1:1:48:Macintosh PPC (25)
32768:255:1380:1:53:0:1:48:Macintosh PPC (26)
32768:255:1400:1:0:0:1:48:Macintosh PPC (27)
32768:255:1402:1:0:0:1:48:Macintosh PPC (28)
32768:255:1407:1:0:0:1:48:Macintosh PPC (29)
32768:255:1414:1:0:0:1:48:Macintosh PPC (30)
32768:255:1432:1:0:0:1:48:Macintosh PPC (31)
32768:255:1432:1:12:0:1:48:Macintosh PPC (32)
32768:255:1432:1:17:0:1:48:Macintosh PPC (33)
32768:255:1445:1:0:0:1:48:Macintosh PPC (34)
32768:255:1460:1:195:0:1:48:Macintosh PPC (35)
32768:255:1474:1:0:0:1:48:Macintosh PPC (36)
32768:255:1484:1:0:0:1:48:Macintosh PPC (37)
32768:255:4450:1:0:0:1:48:Macintosh PPC (38)
32768:255:4460:1:0:0:1:48:Macintosh PPC (39)
32768:255:512:1:0:0:1:48:Macintosh PPC (40)
32768:255:512:1:194:0:1:48:Macintosh PPC (41)
32768:255:536:1:0:0:1:48:Macintosh PPC (42)
32768:255:9138:1:0:0:1:48:Macintosh PPC (43)
36000:64:1460:1:-1:0:0:44:Macintosh PPC (44)
36000:64:1460:1:0:0:1:60:Macintosh PPC (45)
40000:64:1460:1:0:0:1:60:Macintosh PPC (46)
48000:64:1380:1:0:0:1:60:Macintosh PPC (47)
65535:64:1372:1:1:0:1:60:Macintosh PPC (48)
65535:64:1380:1:1:0:1:60:Macintosh PPC (49)
65535:64:1452:1:-1:0:0:44:Macintosh PPC (50)
65535:64:1452:1:1:0:1:60:Macintosh PPC (51)
65535:64:1460:1:-1:0:0:44:Macintosh PPC Mac OS X (10.2.1 and v?) (1)
65535:64:1460:1:1:0:1:60:Macintosh PPC Mac OS X (10.2.1 and v?) (2)
65535:64:1460:1:3:0:1:60:Macintosh PPC (52)
8192:114:1439:1:-1:0:0:44:Windows 2000 (11)
