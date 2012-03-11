/*

   p0f - daemon query interface
   ----------------------------

   This is an interface to be used on the local socket created with
   -Q. 

   Copyright (C) 2003-2004 by Michal Zalewski <lcamtuf@coredump.cx>

*/

#ifndef _HAVE_P0FQUERY_H
#define _HAVE_P0FQUERY_H

#include "types.h"
#include "config.h"

#define QUERY_MAGIC		0x0defaced

#define NO_SCORE		-100

/* Masquerade detection flags: */
#define D_GENRE   0x0001
#define D_DETAIL  0x0002
#define D_LINK    0x0004
#define D_DIST    0x0008
#define D_NAT     0x0010
#define D_FW      0x0020
#define D_NAT2_1  0x0040
#define D_FW2_1   0x0080
#define D_NAT2_2  0x0100
#define D_FW2_2   0x0200
#define D_FAST    0x0400
#define D_TNEG    0x0800

#define D_TIME    0x4000
#define D_FAR     0x8000


struct p0f_query {
  _u32 magic;			/* must be set to QUERY_MAGIC */
  _u32 id;			/* Unique query ID */
  _u32 src_ad,dst_ad;		/* src address, local dst addr */
  _u16 src_port,dst_port;	/* src and dst ports */
};

#define RESP_OK		0	/* Response OK */
#define RESP_BADQUERY	1	/* Query malformed */
#define RESP_NOMATCH	2	/* No match for src-dst data */

struct p0f_response {
  _u32 magic;			/* QUERY_MAGIC */
  _u32 id;			/* Query ID (copied from p0f_query) */
  _u8  type;			/* RESP_* */
  _u8  genre[20];		/* OS genre (empty if no match) */
  _u8  detail[40];		/* OS version (empty if no match) */
  _s8  dist;			/* Distance (-1 if unknown ) */
  _u8  link[30];		/* Link type (empty if unknown) */
  _u8  tos[30];			/* Traffic type (empty if unknown) */
  _u8  fw,nat;			/* firewall and NAT flags flags */
  _u8  real;			/* A real operating system? */
  _s16 score;			/* Masquerade score (or NO_SCORE) */
  _u16 mflags;			/* Masquerade flags (D_*) */
  _s32 uptime;			/* Uptime in hours (-1 = unknown) */
};


/* --------------------------------------- */
/* This is an internal API, do not bother: */
/* --------------------------------------- */

void p0f_initcache(_u32 csiz);

void p0f_addcache(_u32 saddr,_u32 daddr,_u16 sport,_u16 dport,
                  _u8* genre,_u8* detail,_s8 dist,_u8* link,_u8* tos,
                  _u8 fw,_u8 nat,_u8 real,_u16 mss,_u32 signo,
                  _s32 uptime);

void p0f_handlequery(_s32 sock,struct p0f_query* q);

_s16 p0f_findmasq(_u32 sad,_u8* genre,_s8 dist,_u16 mss,
                  _u8 nat,_u8 fw,_u32 signo,_s32 uptime);

void p0f_descmasq(void);

#endif /* ! _HAVE_P0FQUERY_H */
