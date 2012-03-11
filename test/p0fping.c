/*
   p0fping - sample p0f socket ping code
   ---------------------------------

   Just to show how one can find out a priori wheather p0f is alive
   and its query socket reliable before quering it for fingerprints.
   That kind of knowledge is probably useful during startup of misc
   services using p0f. When p0f is working useful statistics can be
   gathered.

   Copyright (C) 2006 by Mariusz Kozlowski <m.kozlowski@tuxland.pl>

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
  struct p0f_query q;
  struct p0f_status s;
  _s32 sock;

  if (argc != 2) {
    debug("Usage: %s p0f_socket\n", argv[0]);
    exit(1);
  }

  sock = socket(PF_UNIX,SOCK_STREAM,0);
  if (sock < 0) pfatal("socket");

  memset(&x,0,sizeof(x));
  x.sun_family = AF_UNIX;
  strncpy(x.sun_path,argv[1],63);   
  if (connect(sock,(struct sockaddr*)&x,sizeof(x))) pfatal(argv[1]);

  q.magic    = QUERY_MAGIC;
  q.id       = 0xabcddcba;
  q.type     = QTYPE_STATUS;

  if (write(sock,&q,sizeof(q)) != sizeof(q))
    fatal("Socket write error (timeout?).\n");

  if (read(sock,&s,sizeof(s)) != sizeof(s))
    fatal("Response read error (timeout?).\n");

  debug("[+] Sufficient socket permissions.\n");

  if (s.magic != QUERY_MAGIC)
    fatal("Bad response magic.\n");

  if (s.id != 0xabcddcba)
    fatal("Bad response ID.\n");

  if (s.type != RESP_STATUS)
    fatal("P0f did not honor our query.\n");

  debug("[+] Got correct p0f status response.\n");
  debug("[i] p0f version          : %s\n", s.version);
  debug("[i] p0f mode             : %s\n", 
    s.mode=='S'?"SYN":(s.mode=='A'?"SYN+ACK":(s.mode=='R'?"RST":(s.mode=='O'?"stray":"unknown"))));
  debug("[i] p0f fp file checksum : 0x%08x\n", s.fp_cksum);
  debug("[i] received packets     : %u\n", s.packets);
  debug("[i] matched packets      : %u\n", s.matched);
  debug("[i] p0f query cache size : %u\n", s.cache);
  debug("[i] cache queries        : %u\n", s.queries);
  debug("[i] cache misses         : %u\n", s.cmisses);
  debug("[i] p0f process uptime   : %u seconds\n", s.uptime);

  shutdown(sock,2);
  close(sock);

  return 0;
}
