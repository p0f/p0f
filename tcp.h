#include <sys/types.h>

#ifdef _SUN_
typedef     unsigned char u_int8_t;
typedef     unsigned int u_int32_t;
#endif

#define	TCPOPT_EOL		0
#define	TCPOPT_NOP		1
#define	TCPOPT_MAXSEG		2
#define TCPOPT_WSCALE   	3
#define TCPOPT_SACKOK   	4
#define TCPOPT_TIMESTAMP        8

#define EXTRACT_16BITS(p) \
        ((u_short)*((u_char *)(p) + 0) << 8 | \
        (u_short)*((u_char *)(p) + 1))

#define IP_DF   0x4000	/* dont fragment flag */
#define IP_MF   0x2000	/* more fragments flag */

#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20

struct iphdr {
  u_char  ihl;
  u_char  tos;		/* type of service */
  short   tot_len;	/* total length */
  u_short id;		/* identification */
  short   off;		/* fragment offset field */
  u_char  ttl;		/* time to live */
  u_char  protocol;	/* protocol */
  u_short check;	/* checksum */
  u_long  saddr; 
  u_long  daddr;        /* source and dest address */
};

typedef	u_long	tcp_seq;

struct tcphdr {
	u_short	th_sport;		/* source port */
	u_short	th_dport;		/* destination port */
	tcp_seq	th_seq;			/* sequence number */
	tcp_seq	th_ack;			/* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN
        u_int8_t th_x2:4;           /* (unused) */
        u_int8_t th_off:4;          /* data offset */
#else /* __BYTE_ORDER == __BIG_ENDIAN */
        u_int8_t th_off:4;          /* data offset */
        u_int8_t th_x2:4;           /* (unused) */
#endif			 
	u_char	th_flags;
	u_short	th_win;			/* window */
	u_short	th_sum;			/* checksum */
	u_short	th_urp;			/* urgent pointer */
};

