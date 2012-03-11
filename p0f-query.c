/*

   p0f - daemon query interface
   ----------------------------

   See p0f-query.h. This is just an internal cache / query
   handling for -Q functionality.

   Copyright (C) 2003 by Michal Zalewski <lcamtuf@coredump.cx>

*/

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "p0f-query.h"
#include "types.h"
#include "config.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif /* ! MSG_NOSIGNAL */

struct cache_data {
  _u32 sad,dad,ports;
  struct p0f_response s;
};

static struct cache_data c[QUERY_CACHE];
static _u32 cur_c;

void p0f_addcache(_u32 saddr,_u32 daddr,_u16 sport,_u16 dport,
                  _u8* genre,_u8* detail,_s8 dist,_u8* link,_u8* tos,
                  _u8 fw,_u8 nat) {

  struct cache_data* cur = c + cur_c;
  struct p0f_response* sc = &cur->s;

  cur->sad   = saddr;
  cur->dad   = daddr;
  cur->ports = (sport << 16) + dport;

  bzero(sc,sizeof(sc));

  if (genre) {
    strncpy(sc->genre,genre,19);
    strncpy(sc->detail,detail,39);
  }

  if (link) strncpy(sc->link,link,29);
  if (tos) strncpy(sc->tos,tos,29);

  sc->dist    = dist;
  sc->fw      = fw;
  sc->nat     = nat;

  cur_c = (cur_c + 1) % QUERY_CACHE;

}


void p0f_handlequery(_s32 sock,struct p0f_query* q) {

  _u32 i;

  if (q->magic != QUERY_MAGIC) {
    struct p0f_response r;
    bzero(&r,sizeof(r));
    r.magic = QUERY_MAGIC;
    r.type  = RESP_BADQUERY;
    r.id    = q->id;
    send(sock,&r,sizeof(r),MSG_NOSIGNAL);
    return;
  }

#define SUBMOD(val,max)	((val) < 0 ? ((max) + (val)) : (val))

  for (i=1;i<QUERY_CACHE;i++) {

    /* We look back from cur_c-1 */

    struct p0f_response* n = &c[SUBMOD(cur_c-i,QUERY_CACHE)].s;

    if (c[i].sad == q->src_ad &&
        c[i].dad == q->dst_ad &&
        c[i].ports == (q->src_port << 16) + q->dst_port) {

        n->magic = QUERY_MAGIC;
        n->type  = RESP_OK;
        n->id    = q->id;
        send(sock,n,sizeof(struct p0f_response),MSG_NOSIGNAL);
        return;

    }
  }

  {
    struct p0f_response r;
    bzero(&r,sizeof(r));
    r.magic = QUERY_MAGIC;
    r.type  = RESP_NOMATCH;
    r.id    = q->id;
    r.dist  = -1;
    send(sock,&r,sizeof(r),MSG_NOSIGNAL);
  }

}


