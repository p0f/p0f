/*
   sendsyn - SYN+ACK trigger
   -------------------------

   This is a trivial code to send a SYN packet to a remote host. The main 
   purpose of this is to trigger a clean SYN+ACK or RST+ACK ("connection
   refused") response that can be compared to the signature you've obtained 
   the usual way. By comparing WSS and other parameters, it is possible to 
   determine how much of the signature changes depending on the initial SYN, 
   which is crucial in some cases (see p0fa.fp and p0fr.fp).

   THIS CODE IS NOT SUITABLE FOR GATHERING "Connection dropped" SIGNATURES.

   Run p0f in the background in -A mode (or -R, if you are interested in
   RST+ACK packet), then run sendsyn, observe results, if any. The code uses a 
   distinct WSS of 12345. If you see it in the SYN+ACK (RST+ACK) response, you 
   need to wildcard the WSS value in your new signature (p0f does the
   first step for you).

   Linux code, may not work on systems that use different mechanism to
   access raw sockets.

   Copyright (C) 2003-2006 by Michal Zalewski <lcamtuf@coredump.cx>

 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <errno.h>

#include "../types.h"

#define fatal(x) do { perror(x); exit(1); } while (0)

static _u8 synpacket[] = {

  /* IP HEADER */

  /* IHL    */ 0x45,
  /* ToS    */ 0x00,
  /* totlen */ 0x00, 0x28,
  /* ID     */ 0x00, 0x00,
  /* offset */ 0x00, 0x00,
  /* TTL    */ 0xFF,
  /* proto  */ 0x06,
  /* cksum */  0x00, 0x00,
  /* saddr */  0, 0, 0, 0,   /* src: [12] */
  /* daddr */  0, 0, 0, 0,   /* dst: [16] */

  /* TCP HEADER - [20] */

  /* sport */  0xCA, 0xFE,
  /* dport */  0, 0,	     /* dp: [22] */
  /* SEQ   */  0x0D, 0xEF, 0xAC, 0xED,
  /* ACK   */  0xDE, 0xAD, 0xBE, 0xEF,
  /* doff  */  0x50,
  /* flags */  0x02,         /* just SYN */
  /* wss   */  0x30, 0x39,   /* 12345 */
  /* cksum */  0x00, 0x00,
  /* urg   */  0x00, 0x00

};


_u16 simple_tcp_cksum(void) {
  _u32 sum = 26 /* tcp, len 20 */;
  _u8  i;
  _u8* p = synpacket + 20;

  for (i=0;i<10;i++) {
    sum += (*p << 8) + *(p+1);
    p+=2;
  }

  p = synpacket + 12;
  
  for (i=0;i<4;i++) {
    sum += (*p << 8) + *(p+1);
    p+=2;
  }

  return ~(sum + (sum >> 16));

}



int main(int argc, char** argv) {

  static struct sockaddr_in sain;
  _s32 sad,dad;
  _s32 sock, one = 1;
  _u16 p,ck;

  if (argc - 4 || (sad=inet_addr(argv[1])) == INADDR_NONE || 
     (dad=inet_addr(argv[2])) == INADDR_NONE || !(p=atoi(argv[3]))) {
    fprintf(stderr,"Usage: %s src_ip dst_ip port\n",argv[0]);
    exit(1);
  }
 
  sock=socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
  
  if (sock<0) fatal("socket");
  
  if (setsockopt(sock,IPPROTO_IP,IP_HDRINCL,(char *)&one,sizeof(one)))
    fatal("setsockopt");
    
  sain.sin_family = AF_INET;
  memcpy(&sain.sin_addr.s_addr,&dad,4);
  memcpy(synpacket+12,&sad,4);
  memcpy(synpacket+16,&dad,4);

  p=htons(p);
  memcpy(synpacket+22,&p,2);

  ck=simple_tcp_cksum();
  ck=htons(ck);
  memcpy(synpacket+36,&ck,2);

  if (sendto(sock,synpacket,sizeof(synpacket), 0,(struct sockaddr *)&sain,
    sizeof(struct sockaddr)) < 0) perror("sendto");
  else 
    printf("Bland SYN sent to %s to port %d.\n",argv[2],ntohs(p));

  return 0;
  
}

