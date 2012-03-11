/*
   sendack2 - RST trigger with data payload
   ----------------------------------------

   See sendack.c for more information. The only difference is that this
   tool sends a packet with a payload to check for some silly implementations
   that bounce the payload back or do other magic.

   THIS PROGRAM IS NOT SUITABLE FOR GATHERING "Connection refused" SIGNATURES.

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
  /* totlen */ 0x00, 0x28 + 4,
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
  /* flags */  0x10,         /* just ACK */
  /* wss   */  0x30, 0x39,   /* 12345 */
  /* cksum */  0x00, 0x00,
  /* urg   */  0x00, 0x00,

  /* PAYLOAD - 80 bytes. Please keep this message intact. */

  0x43,0x6f,0x6e,0x74,0x61,0x63,0x74,0x20,
  0x6c,0x63,0x61,0x6d,0x74,0x75,0x66,0x40,
  0x63,0x6f,0x72,0x65,0x64,0x75,0x6d,0x70,
  0x2e,0x63,0x78,0x20,0x69,0x66,0x20,0x79,
  0x6f,0x75,0x20,0x61,0x72,0x65,0x20,0x63,
  0x75,0x72,0x69,0x6f,0x75,0x73,0x20,0x61,
  0x62,0x6f,0x75,0x74,0x20,0x74,0x68,0x65,
  0x20,0x70,0x75,0x72,0x70,0x6f,0x73,0x65,
  0x20,0x6f,0x66,0x20,0x74,0x68,0x69,0x73,
  0x20,0x70,0x61,0x63,0x6b,0x65,0x74,0x2e

};


_u16 simple_tcp_cksum(void) {
  _u32 sum = 6 + 20 + 80 /* proto tcp (6), tcp len 20 + 80 */;
  _u8  i;
  _u8* p = synpacket + 20;

  for (i=0;i<10 + 40;i++) {
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
    printf("Stray ACK (with data) sent to %s to port %d.\n",argv[2],ntohs(p));

  return 0;
  
}

