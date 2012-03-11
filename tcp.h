/*

   p0f - portable TCP/IP headers
   -----------------------------

   Well.

   Copyright (C) 2003-2006 by Michal Zalewski <lcamtuf@coredump.cx>

*/

#ifndef _HAVE_TCP_H
#define _HAVE_TCP_H

#include "types.h"

#define	TCPOPT_EOL		0	/* End of options */
#define	TCPOPT_NOP		1	/* Nothing */
#define	TCPOPT_MAXSEG		2	/* MSS */
#define TCPOPT_WSCALE   	3	/* Window scaling */
#define TCPOPT_SACKOK   	4	/* Selective ACK permitted */
#define TCPOPT_TIMESTAMP        8	/* Stamp out timestamping! */

#define IP_DF   0x4000	/* dont fragment flag */
#define IP_MF   0x2000	/* more fragments flag */

#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
/* Stupid ECN flags: */
#define TH_ECE  0x40
#define TH_CWR  0x80

struct ip_header {
  _u8  ihl,	/* IHL */
       tos;	/* type of service */
  _u16 tot_len,	/* total length */
       id,	/* identification */
       off;	/* fragment offset + DF/MF */
  _u8  ttl,	/* time to live */
       proto; 	/* protocol */
  _u16 cksum;	/* checksum */
  _u32 saddr,   /* source */
       daddr;   /* destination */
};


struct tcp_header {
  _u16 sport,	/* source port */
       dport;	/* destination port */
  _u32 seq,	/* sequence number */
       ack;	/* ack number */
#if BYTE_ORDER == LITTLE_ENDIAN
  _u8  _x2:4,	/* unused */
       doff:4;	/* data offset */
#else /* BYTE_ORDER == BIG_ENDIAN */
  _u8  doff:4,  /* data offset */
       _x2:4;	/* unused */
#endif			 
  _u8  flags;	/* flags, d'oh */
  _u16 win;	/* wss */
  _u16 cksum;	/* checksum */
  _u16 urg;	/* urgent pointer */
};

#endif /* ! _HAVE_TCP_H */
