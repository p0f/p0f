/* 
   p0fq - sample p0f query interface
   ---------------------------------

   Just to show how things should be done, and perhaps to provide
   a truly ineffective way of querying p0f from shell scripts and
   such.

   If you want to query p0f from a production application, just
   implement the same functionality in your code. It's perhaps 10
   lines.

   Copyright (C) 2003-2006 by Michal Zalewski <lcamtuf@coredump.cx>

  */

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <netinet/in.h>

#include "../types.h"
#include "../p0f-query.h"

#define debug(x...) fprintf(stderr,x)
#define fatal(x...) do { debug("[-] ERROR: " x); exit(2); } while (0)
#define pfatal(x)   do { debug("[-] ERROR: "); perror(x); exit(2); } while (0)


int main(int argc,char** argv) {
  struct sockaddr_un x;
  struct p0f_query p;
  struct p0f_response r;
  _u32 s,d,sp,dp;
  _s32 sock;
  
  if (argc != 6) {
    debug("Usage: %s p0f_socket src_ip src_port dst_ip dst_port\n",
	  argv[0]);
    exit(1);
  }

  s  = inet_addr(argv[2]);
  sp = atoi(argv[3]);
  d  = inet_addr(argv[4]);
  dp = atoi(argv[5]);

  if (!sp || !dp || s == INADDR_NONE || d == INADDR_NONE)
    fatal("Bad IP/port values.\n");

  sock = socket(PF_UNIX,SOCK_STREAM,0);
  if (sock < 0) pfatal("socket");

  memset(&x,0,sizeof(x));
  x.sun_family=AF_UNIX;
  strncpy(x.sun_path,argv[1],63);

  if (connect(sock,(struct sockaddr*)&x,sizeof(x)))  pfatal(argv[1]);

  p.magic    = QUERY_MAGIC;
  p.id       = 0x12345678;
  p.type     = QTYPE_FINGERPRINT;
  p.src_ad   = s;
  p.dst_ad   = d;
  p.src_port = sp;
  p.dst_port = dp;

  if (write(sock,&p,sizeof(p)) != sizeof(p)) 
    fatal("Socket write error (timeout?).\n");

  if (read(sock,&r,sizeof(r)) != sizeof(r))
    fatal("Response read error (timeout?).\n");

  if (r.magic != QUERY_MAGIC)
    fatal("Bad response magic.\n");

  if (r.type == RESP_BADQUERY)
    fatal("P0f did not honor our query.\n");

  if (r.type == RESP_NOMATCH) {
    printf("This connection is not (no longer?) in the cache.\n");
    exit(3);
  }

  if (!r.genre[0]) {
    printf("Genre and OS details not recognized.\n");
  } else {
    printf("Genre    : %s\n",r.genre);
    printf("Details  : %s\n",r.detail);
    if (r.dist != -1) printf("Distance : %d hops\n",r.dist);
  }

  if (r.link[0]) printf("Link     : %s\n",r.link);
  if (r.tos[0])  printf("Service  : %s\n",r.tos);

  if (r.uptime != -1)  printf("Uptime   : %d hrs\n",r.uptime);

  if (r.score != NO_SCORE) 
    printf("M-Score  : %d%% (flags %x).\n",r.score,r.mflags);

  if (r.fw) printf("The host is behind a firewall.\n");
  if (r.nat) printf("The host is behind NAT or such.\n");

  shutdown(sock,2);
  close(sock);

  return 0;
}
