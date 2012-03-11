/*

   p0f - daemon query interface
   ----------------------------

   This is an interface to be used on the local socket created with
   -Q. 

   Be sure to use the most recent version of libpcap when using this
   functionality to avoid needless query processing delays.

   Copyright (C) 2003 by Michal Zalewski <lcamtuf@coredump.cx>

*/

#ifndef _HAVE_P0FQUERY_H
#define _HAVE_P0FQUERY_H

#include "types.h"
#include "config.h"

#define QUERY_MAGIC		0x0defaced

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
};


/* --------------------------------------- */
/* This is an internal API, do not bother: */
/* --------------------------------------- */

void p0f_addcache(_u32 saddr,_u32 daddr,_u16 sport,_u16 dport,
                  _u8* genre,_u8* detail,_s8 dist,_u8* link,_u8* tos,
                  _u8 fw,_u8 nat);

void p0f_handlequery(_s32 sock,struct p0f_query* q);

#endif /* ! _HAVE_P0FQUERY_H */
