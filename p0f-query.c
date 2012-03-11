/*

   p0f - daemon query interface
   ----------------------------

   See p0f-query.h. This is just an internal cache / query
   handling for -Q functionality. Uses the same cache for -M lookups,
   too.

   OPTIMIZE THIS CODE. It blows. At the very least, fill out genre, detail, 
   ToS and link type on lookup.

   Copyright (C) 2003-2006 by Michal Zalewski <lcamtuf@coredump.cx>

*/

#include <stdio.h>
#include <stdlib.h>
#ifndef WIN32
#include <unistd.h>
#include <sys/socket.h>
#endif
#include <string.h>

#include <time.h>
#include <sys/types.h>

#include "p0f-query.h"
#include "types.h"
#include "config.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif /* ! MSG_NOSIGNAL */

struct cache_data {
  _u32 sad,dad,ports,signo;
  _u16 mss;
  struct p0f_response s;
};

static struct cache_data (*c)[];
static _s32 cur_c;
static _s32 QUERY_CACHE;
static _u16 flags;
static _s16 score = NO_SCORE;

/* Imports for statistics */
_u32 packet_count, matched_packets, st_time, file_cksum;
_u8  operating_mode;

#define SAD_HASH(a)	((((a) << 16) ^ ((a) << 8) ^ (a)))

void p0f_initcache(_u32 csiz) {
  QUERY_CACHE = csiz;
  c = calloc(csiz, sizeof(struct cache_data));
  if (!c) {
    fprintf(stderr,"[!] ERROR: Not enough memory for query cache.\n");
    exit(1);
  }
}


void p0f_addcache(_u32 saddr,_u32 daddr,_u16 sport,_u16 dport,
                  _u8* genre,_u8* detail,_s8 dist,_u8* link,_u8* tos,
                  _u8 fw,_u8 nat,_u8 real,_u16 mss,_u32 signo,_s32 uptime) {

  struct cache_data* cur = *c + cur_c;
  struct p0f_response* sc = &cur->s;

  cur->signo = signo;
  cur->mss   = mss;
  cur->sad   = saddr;
  cur->dad   = daddr;
  cur->ports = (sport << 16) + dport;

  memset(sc,0,sizeof(sc));
  if (genre) {
    strncpy(sc->genre,genre,19);
    strncpy(sc->detail,detail,39);
  }

  if (link) strncpy(sc->link,link,29);
  if (tos) strncpy(sc->tos,tos,29);

  sc->score   = real ? score : NO_SCORE;
  sc->mflags  = real ? flags : 0;
  sc->dist    = dist;
  sc->fw      = fw;
  sc->nat     = nat;
  sc->real    = real;
  sc->uptime  = uptime;

  cur_c = (cur_c + 1) % QUERY_CACHE;

}


#define SUBMOD(val,max)	((val) < 0 ? ((max) + (val)) : (val))

#ifndef WIN32

static _u32 qcount, mcount;

void p0f_handlequery(_s32 sock,struct p0f_query* q,_u8 wild) {

  _s32 i;

  if (q->magic != QUERY_MAGIC || 
      (q->type != QTYPE_FINGERPRINT && q->type != QTYPE_STATUS)) {
    struct p0f_response r;
    bzero(&r,sizeof(r));
    r.magic = QUERY_MAGIC;
    r.type  = RESP_BADQUERY;
    r.id    = q->id;
    send(sock,&r,sizeof(r),MSG_NOSIGNAL);
    return;
  }
  
  if (q->type == QTYPE_STATUS) {
    struct p0f_status s;
    s.magic    = QUERY_MAGIC;
    s.id       = q->id;
    s.type     = RESP_STATUS;
    s.mode     = operating_mode;
    s.fp_cksum = file_cksum;
    s.cache    = QUERY_CACHE;
    s.packets  = packet_count;
    s.matched  = matched_packets;
    s.queries  = qcount;
    s.cmisses  = mcount;
    s.uptime   = time(0) - st_time;
    
    strncpy(s.version, VER, sizeof(s.version)-1);
    s.version[sizeof(s.version)-1]=0;
  
    send(sock,&s,sizeof(struct p0f_status),MSG_NOSIGNAL);
    return;
  }
  
  qcount++;
  
  /* Honor wildcards only when src port is 0 */
  if (wild && q->src_port) wild = 0;

  for (i=1;i<QUERY_CACHE;i++) {

    struct cache_data* cur = *c + SUBMOD(cur_c-i,QUERY_CACHE);

    if (cur->sad == q->src_ad &&
        cur->dad == q->dst_ad &&
	( wild ? ((cur->ports & 0xffff) == q->dst_port) :
	(cur->ports == (q->src_port << 16) + q->dst_port))) {
        struct p0f_response* n = &cur->s;
        n->magic = QUERY_MAGIC;
        n->type  = RESP_OK;
        n->id    = q->id;
        send(sock,n,sizeof(struct p0f_response),MSG_NOSIGNAL);
        return;

    }
  }

  {
    struct p0f_response r;
    mcount++;
    bzero(&r,sizeof(r));
    r.magic = QUERY_MAGIC;
    r.type  = RESP_NOMATCH;
    r.id    = q->id;
    r.dist  = -1;
    send(sock,&r,sizeof(r),MSG_NOSIGNAL);
  }

}
#endif /* !WIN32 */


void p0f_descmasq(void) {
  if (flags & D_GENRE)  printf("OS "); 
  if (flags & D_DETAIL) printf("VER ");
  if (flags & D_LINK)   printf("LINK "); 
  if (flags & D_DIST)   printf("DIST ");
  if (flags & D_NAT)    printf("xNAT ");
  if (flags & D_FW)     printf("xFW ");
  if (flags & D_NAT2_1) printf("NAT1 ");
  if (flags & D_NAT2_2) printf("NAT2 ");
  if (flags & D_FW2_1)  printf("FW1 ");
  if (flags & D_FW2_2)  printf("FW2 ");
  if (flags & D_FAST)   printf("FAST ");
  if (flags & D_TNEG)   printf("TNEG ");
  if (flags & D_TIME)   printf("-time ");
  if (flags & D_FAR)    printf("-far ");
}

  

_s16 p0f_findmasq(_u32 sad,_u8* genre,_s8 dist,_u16 mss,
                  _u8 nat,_u8 fw,_u32 signo,_s32 uptime) {

  _s32 i;
  _s16 pscore = 0;

  score = 0;
  flags = 0;

  /* We assume p0f_addcache is called immediately after p0f_findmasq. */

  for (i=1;i<QUERY_CACHE;i++) {
  
    _u16 of = flags;    
    struct cache_data* cur = *c + SUBMOD(cur_c-i,QUERY_CACHE);

    if (cur->sad != sad) continue;
    if (!cur->s.real) continue;

    if (cur->s.score > pscore) pscore = cur->s.score;

    if (mss ^ cur->mss)     flags |= D_LINK;
    if (dist ^ cur->s.dist) flags |= D_DIST;

    if (uptime >= 0 && cur->s.uptime >= 0) {
      _s32 td = uptime - cur->s.uptime;
      if (td < 0)                flags |= D_TNEG;
      else if (td > MAX_TIMEDIF) flags |= D_FAST;
      else                       flags |= D_TIME;
    }
      
    
    if (signo ^ cur->signo) {
      flags |= D_DETAIL;
      if (strcmp(genre,cur->s.genre)) flags |= D_GENRE;
      if (fw)                         flags |= D_FW2_1;
      if (cur->s.fw)                  flags |= D_FW2_2;
      if (nat)                        flags |= D_NAT2_1;
      if (cur->s.nat)                 flags |= D_NAT2_2;
    } else {
      if (nat ^ cur->s.nat) flags |= D_NAT;
      if (fw ^ cur->s.fw)   flags |= D_FW;
    }
    
    if (!of && flags && i > QUERY_CACHE/2) flags |= D_FAR;

  }
  
  if (!flags) return 0;
  
  if (flags & D_DETAIL) score = 4; else score = -3;
  if (flags & D_GENRE)  score += 2;
  if (flags & D_LINK)   score += 4;
#ifdef DIST_EXTRASCORE
  if (flags & D_DIST)   score += 4;
#else
  if (flags & D_DIST)   score++;
#endif /* ^DIST_EXTRASCORE */
  if (flags & D_NAT)    score += 4;
  if (flags & D_FW)     score += 4;
  
  if (flags & D_NAT2_1) score++;
  if (flags & D_NAT2_2) score++;
  if (flags & D_FW2_1)  score++;
  if (flags & D_FW2_2)  score++;

  if (flags & D_TIME)  score++;
  if (flags & D_TNEG)  score+=2;

  if (flags & D_FAR)    score >>= 1;
  if (flags & D_TIME)   if (score) score -=1;

  /* Avoid reporting a host multiple times if it already got reported
     with this or higher score, for as long as its entry lives in the
     cache, of course. Also, carry the highest score to the most 
     recent entry. */

  if (pscore >= score) return 0;  
  return score * 200 / 25;

}
