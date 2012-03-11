/*
 
  p0f - passive OS fingerprinting 
  -------------------------------

  "If you sit down at a poker game and don't see a sucker, 
  get up. You're the sucker."

  (C) Copyright 2000-2003 by Michal Zalewski <lcamtuf@coredump.cx>
  WIN32 port (C) Copyright 2003 by Michael A. Davis <mike@datanerds.net>

*/

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifndef WIN32
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <netdb.h>
#  include <sys/socket.h>
#  include <sys/un.h>
#  include <pwd.h>
#  include <grp.h>
#else
#  include "getopt.h"
#  include <stdarg.h>
#endif /* ^WIN32 */

#include <stdio.h>
#include <pcap.h>
#include <signal.h>

#include <net/bpf.h>
#include <time.h>
#include <ctype.h>

/* #define DEBUG_HASH - display signature hash table stats */

#include "config.h"
#include "types.h"
#include "tcp.h"
#include "mtu.h"
#include "tos.h"
#include "fpentry.h"

#ifndef WIN32
#  include "p0f-query.h"
#endif /* !WIN32 */

#ifdef WIN32

static inline void debug(_u8* format, ...) {
  _u8 buff[1024];
  va_list args;
  va_start(args, format);
  memset(buff, 0, sizeof(buff));
  _vsnprintf( buff, sizeof(buff) - 1, format, args);
  fprintf(stderr, buff);
  va_end(args);
}

static inline void fatal(_u8* format, ...) {
  _u8 buff[1024];
  va_list args;	
  va_start(args, format);
  memset(buff, 0, sizeof(buff));
  vsnprintf( buff, sizeof(buff) - 1, format, args);
  fprintf(stderr, "[-] ERROR: %s", buff);
  va_end(args);
  exit(1);
}

#else
#  define debug(x...)	fprintf(stderr,x)
#  define fatal(x...)	do { debug("[-] ERROR: " x); exit(1); } while (0)
#endif /* ^WIN32 */

#define pfatal(x)	do { debug("[-] ERROR: "); perror(x); exit(1); } while (0)

static struct fp_entry sig[MAXSIGS];
static _u32 sigcnt;

/* By hash */
static struct fp_entry* bh[16];

#define SIGHASH(tsize,optcnt,q,df) \
	(( (_u8) (((tsize) << 1) ^ ((optcnt) << 1) ^ (df) ^ (q) )) & 0x0f)

static _u8 *config_file,
           *use_iface,
           *use_dump,
#ifndef WIN32
           *use_cache,
           *set_user,
#endif /* !WIN32 */
           *use_rule = "tcp[13] & 0x17 == 2";

static _u8 no_extra,
           no_osdesc,
           no_known,
           no_unknown,
           no_banner,
           use_promisc,
           add_timestamp,
           header_len,
           ack_mode,
           go_daemon,
           use_logfile,
           mode_oneline,
           always_sig,
           do_resolve,
           check_collide;

static pcap_t *pt;
static struct bpf_program flt;


static void die_nicely(_s32 sig) {
  if (sig) debug("+++ Exiting on signal %d +++\n",sig);
  if (pt) pcap_close(pt);
  exit(sig);
}


static void set_header_len(_u32 type) {

  switch(type) {

    case DLT_NULL:
    case DLT_SLIP:
    case DLT_RAW:  break;

    case DLT_EN10MB: header_len=14; break;

#ifdef DLT_LOOP
    case DLT_LOOP:
#endif

#ifdef DLT_PPP_SERIAL
    case DLT_PPP_SERIAL: /* NetBSD oddity */
#endif

    case DLT_PPP:    header_len=4; break;

    case DLT_IEEE802:
      header_len=22;
      break;

#ifdef DLT_PFLOG
    case DLT_PFLOG:
      header_len=28;
      break;
#endif

#ifdef DLT_LINUX_SLL
    case DLT_LINUX_SLL:
      header_len=16;
      break;
#endif

    default:
      debug("[!] WARNING: Unknown datalink type %d, assuming no header.\n",type);
      break;

  }

}



static void usage(_u8* name) {
  fprintf(stderr,
          "\nUsage: %s [ -f file ] [ -i device ] [ -s file ] [ -o file ]\n"

#ifndef WIN32
          "       [ -Q sock ] [ -u user ] [ -NDUKASCqtpdlr ] [ 'filter' ]\n"
#else
          "       [ -NDUKASCqtpdlrL ] [ 'filter rule' ]\n"
#endif /* ^WIN32 */

          "  -f file   - read fingerprints from file\n"
          "  -i device - listen on this device\n"
          "  -s file   - read packets from tcpdump snapshot\n"
          "  -o file   - write to this logfile (implies -t)\n"
#ifndef WIN32
          "  -Q sock   - listen on local socket for queries\n"
          "  -u user   - chroot and setuid to this user\n"
#endif /* !WIN32 */
          "  -N        - do not report distances and link media\n"
          "  -D        - do not report OS details (just genre)\n"
          "  -U        - do not display unknown signatures\n"
          "  -K        - do not display known signatures (for tests)\n"
          "  -S        - report signatures even for known systems\n"
          "  -A        - go into SYN+ACK mode (semi-supported)\n"
          "  -r        - resolve host names (not recommended)\n"
          "  -q        - be quiet - no banner\n"
          "  -p        - switch card to promiscuous mode\n"
          "  -d        - daemon mode (fork into background)\n"
          "  -l        - use single-line output (easier to grep)\n"
          "  -C        - run signature collision check\n"
#ifdef WIN32
          "  -L        - list all available interfaces\n"
#endif /* ^WIN32 */
          "  -t        - add timestamps to every entry\n\n",name);
  exit(1);
}


static void collide(_u32 id) {
  _u32 i,j;
  _u32 cur;

  if (sig[id].ttl % 32 && sig[id].ttl != 255)
    debug("[!] Unusual TTL (%d) for signature '%s %s' (line %d).\n",
          sig[id].ttl,sig[id].os,sig[id].desc,sig[id].line);

  for (i=0;i<id;i++) {

    if (!strcmp(sig[i].os,sig[id].os) && 
        !strcmp(sig[i].desc,sig[id].desc))
      debug("[!] Duplicate signature name: '%s %s' (line %d and %d).\n",
            sig[i].os,sig[i].desc,sig[i].line,sig[id].line);

    /* If TTLs are sufficiently away from each other, the risk of
       a collision is lower. */
    if (abs((_s32)sig[id].ttl - (_s32)sig[i].ttl) > 25) continue;

    if (sig[id].df ^ sig[i].df) continue;
    if (sig[id].zero_stamp ^ sig[i].zero_stamp) continue;
    if (sig[id].size ^ sig[i].size) continue;
    if (sig[id].optcnt ^ sig[i].optcnt) continue;
    if (sig[id].quirks ^ sig[i].quirks) continue;

    switch (sig[id].wsize_mod) {

      case 0: /* Current: const */

        cur=sig[id].wsize;

do_const:

        switch (sig[i].wsize_mod) {
       
          case 0: /* Previous is also const */

            /* A problem if values match */
            if (cur ^ sig[i].wsize) continue; 
            break;

          case MOD_CONST: /* Current: const, prev: modulo (or *) */

            /* A problem if current value is a multiple of that modulo */
            if (cur % sig[i].wsize) continue;
            break;

          case MOD_MSS: /* Current: const, prev: mod MSS */

            if (sig[i].mss_mod || sig[i].wsize * sig[i].mss != cur)
              continue;

            break;

          case MOD_MTU: /* Current: const, prev: mod MTU */

            if (sig[i].mss_mod || sig[i].wsize * (sig[i].mss+40) != cur)
              continue;

            break;

        }
        
        break;

      case 1: /* Current signature is modulo something */

        /* A problem only if this modulo is a multiple of the 
           previous modulo */

        if (sig[i].wsize_mod != MOD_CONST) continue;
        if (sig[id].wsize % sig[i].wsize) continue;

        break;

      case MOD_MSS: /* Current is modulo MSS */
  
        /* There's likely a problem only if the previous one is close
           to '*'; we do not check known MTUs, because this particular
           signature can be made with some uncommon MTUs in mind. The
           problem would also appear if current signature has a fixed
           MSS. */

        if (sig[i].wsize_mod != MOD_CONST || sig[i].wsize >= 8) {
          if (!sig[id].mss_mod) {
            cur = sig[id].mss * sig[id].wsize;
            goto do_const;
          }
          continue;
        }

        break;

      case MOD_MTU: /* Current is modulo MTU */

        if (sig[i].wsize_mod != MOD_CONST || sig[i].wsize <= 8) {
          if (!sig[id].mss_mod) {
            cur = (sig[id].mss+40) * sig[id].wsize;
            goto do_const;
          }
          continue;
        }
  
        break;

    }

    /* Same for wsc */
    switch (sig[id].wsc_mod) {

      case 0: /* Current: const */

        cur=sig[id].wsc;

        switch (sig[i].wsc_mod) {
       
          case 0: /* Previous is also const */

            /* A problem if values match */
            if (cur ^ sig[i].wsc) continue; 
            break;

          case 1: /* Current: const, prev: modulo (or *) */

            /* A problem if current value is a multiple of that modulo */
            if (cur % sig[i].wsc) continue;
            break;

        }
        
        break;

      case MOD_CONST: /* Current signature is modulo something */

        /* A problem only if this modulo is a multiple of the 
           previous modulo */

        if (!sig[i].wsc_mod) continue;
        if (sig[id].wsc % sig[i].wsc) continue;

        break;

     }

    /* Same for mss */
    switch (sig[id].mss_mod) {

      case 0: /* Current: const */

        cur=sig[id].mss;

        switch (sig[i].mss_mod) {
       
          case 0: /* Previous is also const */

            /* A problem if values match */
            if (cur ^ sig[i].mss) continue; 
            break;

          case 1: /* Current: const, prev: modulo (or *) */

            /* A problem if current value is a multiple of that modulo */
            if (cur % sig[i].mss) continue;
            break;

        }
        
        break;

      case MOD_CONST: /* Current signature is modulo something */

        /* A problem only if this modulo is a multiple of the 
           previous modulo */

        if (!sig[i].mss_mod) continue;
        if (sig[id].mss % sig[i].mss) continue;

        break;

     }

     /* Now check option sequence */

    for (j=0;j<sig[id].optcnt;j++)
      if (sig[id].opt[j] ^ sig[i].opt[j]) goto reloop;

    debug("[!] Signature '%s %s' (line %d)\n"
          "    is already covered by '%s %s' (line %d).\n",
          sig[id].os,sig[id].desc,sig[id].line,sig[i].os,sig[i].desc,
          sig[i].line);

reloop:

    ;

  }

}



static void load_config(_u8* file) {
  _u32 ln=0;
  _u8 buf[MAXLINE];
  _u8* p;
  FILE* c = fopen(file?file:(_u8*)
            (ack_mode?SYNACK_DB:SYN_DB),"r");

  if (!c) {
    if (!file) load_config(ack_mode? CONFIG_DIR "/" SYNACK_DB :
                                     CONFIG_DIR "/" SYN_DB );
      else pfatal(file);
    return;
  }

  while ((p=fgets(buf,sizeof(buf),c))) {
    _u32 l;

    _u8 obuf[MAXLINE],genre[MAXLINE],desc[MAXLINE],quirks[MAXLINE];
    _u8 w[MAXLINE];
    _u32 t,d,s;
    struct fp_entry* e;
      
    ln++;

    /* Remove leading and trailing blanks */
    while (isspace(*p)) p++;
    l=strlen(p);
    while (l && isspace(*(p+l-1))) *(p+(l--)-1)=0;
	
    /* Skip empty lines and comments */
    if (!l) continue;
    if (*p == '#') continue;

    if (sscanf(p,"%[0-9%*ST]:%d:%d:%d:%[^:]:%[^ :]:%[^:]:%[^:]",
                  w,         &t,&d,&s,obuf, quirks,genre,desc) != 8)
      fatal("Syntax error in config line %d.\n",ln);

    if (genre[0] == '*') {
     sig[sigcnt].os           = strdup(genre+1);
     sig[sigcnt].no_detail    = 1;
    } else if (genre[0] == '@') {
     sig[sigcnt].os           = strdup(genre+1);
     sig[sigcnt].generic      = 1;
    } else sig[sigcnt].os     = strdup(genre);

    sig[sigcnt].desc   = strdup(desc);
    sig[sigcnt].ttl    = t;
    sig[sigcnt].size   = s;
    sig[sigcnt].df     = d;
 
    if (w[0] == '*') {
      sig[sigcnt].wsize = 1;
      sig[sigcnt].wsize_mod = MOD_CONST;
    } else if (tolower(w[0]) == 's') {
      sig[sigcnt].wsize_mod = MOD_MSS;
      if (!isdigit(*(w+1))) fatal("Bad Snn value in WSS in line %d.\n",ln);
      sig[sigcnt].wsize = atoi(w+1);
    } else if (tolower(w[0]) == 't') {
      sig[sigcnt].wsize_mod = MOD_MTU;
      if (!isdigit(*(w+1))) fatal("Bad Tnn value in WSS in line %d.\n",ln);
      sig[sigcnt].wsize = atoi(w+1);
    } else if (w[0] == '%') {
      if (!(sig[sigcnt].wsize = atoi(w+1)))
        fatal("Null modulo for window size in config line %d.\n",ln);
      sig[sigcnt].wsize_mod = MOD_CONST;
    } else sig[sigcnt].wsize = atoi(w);

    /* Now let's parse options */

    p=obuf;

    sig[sigcnt].zero_stamp = 1;

    if (*p=='.') p++;

    while (*p) {
      _u8 optcnt = sig[sigcnt].optcnt;
      switch (tolower(*p)) {
        case 'n': sig[sigcnt].opt[optcnt] = TCPOPT_NOP;
                  break;
        case 's': sig[sigcnt].opt[optcnt] = TCPOPT_SACKOK;
                  break;
        case 't': sig[sigcnt].opt[optcnt] = TCPOPT_TIMESTAMP;
                  if (*(p+1)!='0') {
                    sig[sigcnt].zero_stamp=0;
                    if (isdigit(*(p+1))) 
                      fatal("Bogus Tstamp specification in line %d.\n",ln);
                  }
                  break;
        case 'w': sig[sigcnt].opt[optcnt] = TCPOPT_WSCALE;
                  if (p[1] == '*') {
                    sig[sigcnt].wsc = 1;
                    sig[sigcnt].wsc_mod = MOD_CONST;
                  } else if (p[1] == '%') {
                    if (!(sig[sigcnt].wsc = atoi(p+2)))
                      fatal("Null modulo for wscale in config line %d.\n",ln);
                    sig[sigcnt].wsc_mod = MOD_CONST;
                  } else if (!isdigit(*(p+1)))
                    fatal("Incorrect W value in line %d.\n",ln);
                  else sig[sigcnt].wsc = atoi(p+1);
                  break;
        case 'm': sig[sigcnt].opt[optcnt] = TCPOPT_MAXSEG;
                  if (p[1] == '*') {
                    sig[sigcnt].mss = 1;
                    sig[sigcnt].mss_mod = MOD_CONST;
                  } else if (p[1] == '%') {
                    if (!(sig[sigcnt].mss = atoi(p+2)))
                      fatal("Null modulo for MSS in config line %d.\n",ln);
                    sig[sigcnt].mss_mod = MOD_CONST;
                  } else if (!isdigit(*(p+1)))
                    fatal("Incorrect M value in line %d.\n",ln);
                  else sig[sigcnt].mss = atoi(p+1);
                  break;

        /* Yuck! */
        case '?': if (!isdigit(*(p+1)))
                    fatal("Bogus ?nn value in line %d.\n",ln);
                  else sig[sigcnt].opt[optcnt] = atoi(p+1);
                  break;

        default: fatal("Unknown TCP option '%c' in config line %d.\n",*p,ln);
      }

      if (++sig[sigcnt].optcnt >= MAXOPT-1) 
        fatal("Too many TCP options specified in config line %d.\n",ln);

      /* Skip separators */
      do { p++; } while (*p && !isalpha(*p));

    }
 
    /* Append end of options */
    sig[sigcnt].opt[sig[sigcnt].optcnt] = TCPOPT_EOL;
    sig[sigcnt].optcnt++;
    sig[sigcnt].line = ln;

    p = quirks;

    while (*p) 
      switch (toupper(*(p++))) {
        case 'E': sig[sigcnt].quirks |= QUIRK_EOL; break;
        case 'P': sig[sigcnt].quirks |= QUIRK_PAST; break;
        case 'Z': sig[sigcnt].quirks |= QUIRK_ZEROID; break;
        case 'I': sig[sigcnt].quirks |= QUIRK_IPOPT; break;
        case 'U': sig[sigcnt].quirks |= QUIRK_URG; break;
        case 'X': sig[sigcnt].quirks |= QUIRK_X2; break;
        case 'A': sig[sigcnt].quirks |= QUIRK_ACK; break;
        case 'T': sig[sigcnt].quirks |= QUIRK_T2; break;
        case 'F': sig[sigcnt].quirks |= QUIRK_FLAGS; break;
        case 'D': sig[sigcnt].quirks |= QUIRK_DATA; break;
        case '!': sig[sigcnt].quirks |= QUIRK_BROKEN; break;
        case '.': break;
        default: fatal("Bad quirk '%c' in line %d.\n",*(p-1),ln);
      }

    e = bh[SIGHASH(s,sig[sigcnt].optcnt,sig[sigcnt].quirks,d)];

    if (!e) {
      bh[SIGHASH(s,sig[sigcnt].optcnt,sig[sigcnt].quirks,d)] = sig + sigcnt;
    } else {
      while (e->next) e = e->next;
      e->next = sig + sigcnt;
    } 

    if (check_collide) collide(sigcnt);

    if (++sigcnt >= MAXSIGS)
      fatal("Maximum signature count exceeded.\n");

  }

  fclose(c);

#ifdef HASH_DEBUG
  { 
    int i;
    struct fp_entry* p;
    printf("Hash table layout: ");
    for (i=0;i<16;i++) {
      int z=0;
      p = bh[i];
      while (p) { p=p->next; z++; }
      printf("%d ",z);
    }
    printf("\n");
  }
#endif /* HASH_DEBUG */

  if (!sigcnt)
    debug("[!] WARNING: no signatures loaded from config file.\n");

}




static _u8* lookup_link(_u16 mss,_u8 txt) {
  _u32 i;
  static _u8 tmp[32];

  if (!mss) return txt ? "unspecified" : 0;
  mss += 40;
  
  for (i=0;i<MTU_CNT;i++) {
   if (mss == mtu[i].mtu) return mtu[i].dev;
   if (mss < mtu[i].mtu)  goto unknown;
  }

unknown:

  if (!txt) return 0;
  sprintf(tmp,"unknown-%d",mss);
  return tmp;

}


static _u8* lookup_tos(_u8 t) {
  _u32 i;

  if (!t) return 0;

  for (i=0;i<TOS_CNT;i++) {
   if (t == tos[i].tos) return tos[i].desc;
   if (t < tos[i].tos) break;
  }

  return 0;

}


static void put_date(void) {
  _u8* x;
  _u32 i=time(0);
  x=ctime((void*)&i);
  if (x[strlen(x)-1]=='\n') x[strlen(x)-1]=0;
  printf("<%s> ",x);
}


#define MY_MAXDNS 32

static inline _u8* grab_name(_u8* a) {
  struct hostent* r;
  static _u8 rbuf[MY_MAXDNS+6] = "/";
  _u32 j;
  _u8 *s,*d = rbuf+1;

  if (!do_resolve) return "";
  r = gethostbyaddr(a,4,AF_INET);
  if (!r || !(s = r->h_name) || !(j = strlen(s))) return "";
  if (j > MY_MAXDNS) return "";

  while (j--) {
    if (isalnum(*s) || *s == '-' || *s == '.') *d = *s;
      else *d = '?';
    d++; s++;
  }

  *d=0;

  return rbuf;

}


static inline void display_signature(_u8 ttl,_u8 tot,_u8 df,_u8* op,_u8 ocnt,
                                     _u16 mss,_u16 wss,_u8 wsc,_u32 tstamp,
                                     _u32 quirks) {

  _u32 j;
  _u8 d=0;

  if (mss && wss && !(wss % mss)) printf("S%d",wss/mss); else
  if (wss && !(wss % 1460)) printf("S%d",wss/1460); else
  if (mss && wss && !(wss % (mss+40))) printf("T%d",wss/(mss+40)); else
  if (wss && !(wss % 1500)) printf("T%d",wss/1500); else
    printf("%d",wss);

  printf(":%d:%d:%d:",ttl,df,tot);

  for (j=0;j<ocnt;j++) {
    switch (op[j]) {
      case TCPOPT_NOP: printf("N"); d=1; break;
      case TCPOPT_WSCALE: printf("W%d",wsc); d=1; break;
      case TCPOPT_MAXSEG: printf("M%d",mss); d=1; break;
      case TCPOPT_TIMESTAMP: printf("T"); 
        if (!tstamp) printf("0"); d=1; break;
      case TCPOPT_SACKOK: printf("S"); d=1; break;
      case TCPOPT_EOL: goto all_done_known; break;
      default: printf("?%d",op[j]); break;
    }
    if (op[j+1] != TCPOPT_EOL) printf(",");
  }

all_done_known:

  if (!d) printf(".");

  printf(":");

  if (!quirks) printf("."); else {
    if (quirks & QUIRK_EOL) printf("E");
    if (quirks & QUIRK_PAST) printf("P");
    if (quirks & QUIRK_ZEROID) printf("Z");
    if (quirks & QUIRK_IPOPT) printf("I");
    if (quirks & QUIRK_URG) printf("U");
    if (quirks & QUIRK_X2) printf("X");
    if (quirks & QUIRK_ACK) printf("A");
    if (quirks & QUIRK_T2) printf("T");
    if (quirks & QUIRK_FLAGS) printf("F");
    if (quirks & QUIRK_DATA) printf("D");
    if (quirks & QUIRK_BROKEN) printf("!");
  }

}




static inline void find_match(_u8 tot,_u8 df,_u8 ttl,_u16 wss,_u32 src,
                       _u32 dst,_u16 sp,_u16 dp,_u8 ocnt,_u8* op,_u16 mss,
                       _u8 wsc,_u32 tstamp,_u8 tos,_u32 quirks,_u8 ecn) {

  _u32 j;
  _u8* a;
  _u8  n=0;
  struct fp_entry* p;
  _u8  orig_df  = df;
  _u8* tos_desc = 0;

re_lookup:

  p = bh[SIGHASH(tot,ocnt,quirks,df)];

  while (p) {
  
    /* Cheap and specific checks first... */
    if (tot ^ p->size) { p = p->next; continue; }
    if (ocnt ^ p->optcnt) { p = p->next; continue; }
    if (p->ttl < ttl) { p = p->next; continue; }
    if (p->zero_stamp ^ (!tstamp)) { p = p->next; continue; }
    if (p->df ^ df) { p = p->next; continue; }
    if (p->quirks ^ quirks) { p = p->next; continue; }

    /* Naah... can't happen ;-) */
    if (!p->no_detail)
      if (p->ttl - ttl > MAXDIST) { p = p->next; continue; }

    /* Check MSS and WSCALE... */
    if (!p->mss_mod) {
      if (mss ^ p->mss) { p = p->next; continue; }
    } else if (mss % p->mss) { p = p->next; continue; }

    if (!p->wsc_mod) {
      if (wsc ^ p->wsc) { p = p->next; continue; }
    } else if (wsc % p->wsc) { p = p->next; continue; }

    /* Then proceed with the most complex WSS check... */
    switch (p->wsize_mod) {
      case 0:
        if (wss ^ p->wsize) { p = p->next; continue; }
        break;
      case MOD_CONST:
        if (wss % p->wsize) { p = p->next; continue; }
        break;
      case MOD_MSS:
        if (mss && !(wss % mss)) {
          if ((wss / mss) ^ p->wsize) { p = p->next; continue; }
        } else if (!(wss % 1460)) {
          if ((wss / 1460) ^ p->wsize) { p = p->next; continue; }
        } else { p = p->next; continue; }
        break;
      case MOD_MTU:
        if (mss && !(wss % (mss+40))) {
          if ((wss / (mss+40)) ^ p->wsize) { p = p->next; continue; }
        } else if (!(wss % 1500)) {
          if ((wss / 1500) ^ p->wsize) { p = p->next; continue; }
        } else { p = p->next; continue; }
        break;
     }

    /* Numbers agree. Let's check options */

    for (j=0;j<ocnt;j++)
      if (p->opt[j] ^ op[j]) goto continue_this;

    /* Match! */

    if (!no_known) {

      if (add_timestamp) put_date();
      a=(_u8*)&src;

      printf("%d.%d.%d.%d%s:%d - %s ",a[0],a[1],a[2],a[3],grab_name(a),
             sp,p->os);

      if (!no_osdesc) printf("%s ",p->desc);

      if (mss & wss) {
        if (p->wsize_mod == MOD_MSS) {
          if ((wss % mss) && !(wss % 1460)) { n=1; printf("(NAT!) "); }
        } else if (p->wsize_mod == MOD_MTU) {
          if ((wss % (mss+40)) && !(wss % 1500)) { n=1; printf("(NAT2!) "); }
        }
      }

      if (ecn) printf("(ECN) ");
      if (orig_df ^ df) printf("(firewall!) ");

      if (tos) {
        tos_desc = lookup_tos(tos);
        if (tos_desc) printf("[%s] ",tos_desc); else printf("[tos %d] ",tos);
      }

      if (p->generic) printf("[GENERIC] ");

      if (p->no_detail) printf("* "); else
        if (tstamp) printf("(up: %d hrs) ",tstamp/360000);

      if (always_sig || (p->generic && !no_unknown)) {

        if (!mode_oneline) printf("\n  ");
        printf("Signature: [");

        display_signature(ttl,tot,orig_df,op,ocnt,mss,wss,wsc,tstamp,quirks);

        if (p->generic)
          printf(":%s:?] ",p->os);
        else
          printf("] ");

      }

      if (!no_extra && !p->no_detail) {
	a=(_u8*)&dst;
        if (!mode_oneline) printf("\n  ");
        printf("-> %d.%d.%d.%d:%d (distance %d, link: %s)",
               a[0],a[1],a[2],a[3],dp,p->ttl - ttl,
               lookup_link(mss,1));
      }

#ifndef WIN32
      if (use_cache)
        p0f_addcache(src,dst,sp,dp,p->os,p->desc,p->no_detail ? -1 : 
                     (p->ttl - ttl),p->no_detail ? 0 : lookup_link(mss,0),
                     tos_desc, orig_df ^ df, n);
#endif /* !WIN32 */

      printf("\n");
      fflush(0);

    }

    return;

continue_this:

    p = p->next;

  }

  /* Hackish. */
  if (!df) { df = 1; goto re_lookup; }

  if (!no_unknown) { 
    if (add_timestamp) put_date();
    a=(_u8*)&src;
    printf("%d.%d.%d.%d%s:%d - UNKNOWN [",a[0],a[1],a[2],a[3],grab_name(a),sp);

    display_signature(ttl,tot,orig_df,op,ocnt,mss,wss,wsc,tstamp,quirks);

    printf(":?:?] ");

    if (mss & wss) {
      if ((wss % mss) && !(wss % 1460)) { n=1; printf("(NAT!) "); }
      else if ((wss % (mss+40)) && !(wss % 1500)) { n=1; printf("(NAT2!) "); }
    }

    if (ecn) printf("(ECN) ");

    if (tos) {
      tos_desc = lookup_tos(tos);
      if (tos_desc) printf("[%s] ",tos_desc); else printf("[tos %d] ",tos);
    }

    if (tstamp) printf("(up: %d hrs) ",tstamp/360000);

    if (!no_extra) {
      a=(_u8*)&dst;
      if (!mode_oneline) printf("\n  ");
      printf("-> %d.%d.%d.%d:%d (link: %s)",a[0],a[1],a[2],a[3],
               dp,lookup_link(mss,1));
    }

#ifndef WIN32
    if (use_cache)
      p0f_addcache(src,dst,sp,dp,0,0,-1,lookup_link(mss,0),tos_desc,
                   0,n);
#endif /* !WIN32 */

    printf("\n");
    fflush(0);

  }

}


#define GET16(p) \
        ((_u16) *((_u8*)(p)+0) << 8 | \
         (_u16) *((_u8*)(p)+1) )


static void parse(_u8* none, struct pcap_pkthdr *pph, _u8* packet) {
  struct ip_header *iph;
  struct tcp_header *tcph;
  _u8*   end_ptr;
  _u8*   opt_ptr;
  _s32   ilen,olen;

  _u8    op[MAXOPT];
  _u8    ocnt = 0;
  _u16   mss_val = 0, wsc_val = 0;
  _u32   tstamp = 0;
  _u32   quirks = 0;

  end_ptr = packet + pph->len;

  iph = (struct ip_header*)(packet+header_len);

  /* Whoops, IP header ends past end_ptr */
  if ((_u8*)(iph + 1) > end_ptr) return;

  if ( ((iph->ihl & 0x40) != 0x40) || iph->proto != IPPROTO_TCP) {
    debug("[!] WARNING: Non-IP packet received. Bad header_len!\n");
    return;
  }

  /* If the declared length is shorter than the snapshot (etherleak
     or such), truncate this bad boy. */

  opt_ptr = (_u8*)iph + htons(iph->tot_len);
  if (end_ptr > opt_ptr) end_ptr = opt_ptr;

  ilen = iph->ihl & 15;

  /* Borken packet */
  if (ilen < 5) return;

  if (ilen > 5) {

#ifdef DEBUG_EXTRAS
    _u8 i;
    printf("  -- EXTRA IP OPTIONS (packet below): ");
    for (i=0;i<ilen-5;i++) 
      printf("%08x ",(_u32)ntohl(*(((_u32*)(iph+1))+i)));
    printf("\n");
    fflush(0);
#endif /* DEBUG_EXTRAS */

    quirks |= QUIRK_IPOPT;
  }

  tcph = (struct tcp_header*)(packet + header_len + (ilen << 2));
  opt_ptr = (_u8*)(tcph + 1);
    
  /* Whoops, TCP header would end past end_ptr */
  if (opt_ptr > end_ptr) return;

  if (tcph->flags & ~(TH_SYN|TH_ACK|TH_ECE|TH_CWR)) 
    quirks |= QUIRK_FLAGS;

  ilen=((tcph->doff) << 2) - sizeof(struct tcp_header);
  
  if ( (_u8*)opt_ptr + ilen < end_ptr) { 
  
#ifdef DEBUG_EXTRAS
    _u32 i;
    
    printf("  -- EXTRA PAYLOAD (packet below): ");
    
    for (i=0;i< (_u32)end_ptr - ilen - (_u32)opt_ptr;i++)
      printf("%02x ",*(opt_ptr + ilen + i));

    printf("\n");
    fflush(0);
#endif /* DEBUG_EXTRAS */
  
    quirks |= QUIRK_DATA;
   
  }

  while (ilen > 0) {

    ilen--;

    switch (*(opt_ptr++)) {
      case TCPOPT_EOL:  
        /* EOL */
        op[ocnt] = TCPOPT_EOL;
        ocnt++;
        quirks |= QUIRK_EOL;

        if (ilen) {

          quirks |= QUIRK_PAST;

#ifdef DEBUG_EXTRAS

          printf("  -- EXTRA TCP OPTIONS (packet below): ");

          while (ilen) {
            ilen--;
            if (opt_ptr >= end_ptr) { printf("..."); break; }
            printf("%02x ",*(opt_ptr++));
          }

          printf("\n");
          fflush(0);

#endif /* DEBUG_EXTRAS */

        }

        goto end_parsing;

      case TCPOPT_NOP:
        /* NOP */
        op[ocnt] = TCPOPT_NOP;
        ocnt++;
        break;

      case TCPOPT_SACKOK:
        /* SACKOK LEN */
        op[ocnt] = TCPOPT_SACKOK;
        ocnt++; ilen--; opt_ptr++;
        break;
	
      case TCPOPT_MAXSEG:
        /* MSS LEN D0 D1 */
        if (opt_ptr + 3 > end_ptr) {
borken:
          quirks |= QUIRK_BROKEN;
          goto end_parsing;
        }
        op[ocnt] = TCPOPT_MAXSEG;
        mss_val = GET16(opt_ptr+1);
        ocnt++; ilen -= 3; opt_ptr += 3;
        break;

      case TCPOPT_WSCALE:
        /* WSCALE LEN D0 */
        if (opt_ptr + 2 > end_ptr) goto borken;
        op[ocnt] = TCPOPT_WSCALE;
        wsc_val = *(_u8 *)(opt_ptr + 1);
        ocnt++; ilen -= 2; opt_ptr += 2;
        break;

      case TCPOPT_TIMESTAMP:
        /* TSTAMP LEN T0 T1 T2 T3 A0 A1 A2 A3 */
        if (opt_ptr + 9 > end_ptr) goto borken;
        op[ocnt] = TCPOPT_TIMESTAMP;

	memcpy(&tstamp, opt_ptr+5, 4);
        if (tstamp) quirks |= QUIRK_T2;

	memcpy(&tstamp, opt_ptr+1, 4);
        tstamp = ntohl(tstamp);

        ocnt++; ilen -= 9; opt_ptr += 9;
        break;

      default:

        /* Hrmpf... */
        if (opt_ptr + 1 > end_ptr) goto borken;

        op[ocnt] = *(opt_ptr-1);
        olen = *(_u8*)(opt_ptr)-1;
        if (olen > 32 || (olen < 0)) goto borken;

        ocnt++; ilen -= olen; opt_ptr += olen;
        break;

     }

     if (ocnt >= MAXOPT-1) goto borken;

     /* Whoops, we're past end_ptr */
     if (ilen > 0)
       if (opt_ptr >= end_ptr) goto borken;

   }

end_parsing:

   if (!ocnt || op[ocnt-1] != TCPOPT_EOL) {
     op[ocnt] = TCPOPT_EOL;
     ocnt++;
   }

   if (tcph->ack) quirks |= QUIRK_ACK;
   if (tcph->urg) quirks |= QUIRK_URG;
   if (tcph->_x2) quirks |= QUIRK_X2;
   if (!iph->id)  quirks |= QUIRK_ZEROID;

   find_match(
     /* total */ ntohs(iph->tot_len),
     /* DF */    (ntohs(iph->off) & IP_DF) != 0,
     /* TTL */   iph->ttl,
     /* WSS */   ntohs(tcph->win),
     /* src */   iph->saddr,
     /* dst */   iph->daddr,
     /* sp */    ntohs(tcph->sport),
     /* dp */    ntohs(tcph->dport),
     /* ocnt */  ocnt,
     /* op */    op,
     /* mss */   mss_val,
     /* wsc */   wsc_val,
     /* tst */   tstamp,
     /* TOS */   iph->tos,
     /* Q? */    quirks,
     /* ECN */   tcph->flags & (TH_ECE|TH_CWR)
  );

#ifdef DEBUG_EXTRAS

  if (quirks & QUIRK_FLAGS || tcph->ack || tcph->_x2 || tcph->urg) 
    printf("  -- EXTRA TCP VALUES: ACK=0x%x, UNUSED=%d, URG=0x%x "
           "(flags = %x)\n",tcph->ack,tcph->_x2,tcph->urg,tcph->flags);
  fflush(0);

#endif /* DEBUG_EXTRAS */

}



int main(int argc,char** argv) {
  _u8 buf[MAXLINE*4];
  _s32 r;
  _u8 errbuf[PCAP_ERRBUF_SIZE];

#ifdef WIN32
  _u8 ebuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs, *d;
  _s32 adapter, i;
  while ((r = getopt(argc, argv, "f:i:s:o:NDKUqtpArlSdCL")) != -1) 
#else
  _s32 lsock=0;

  if (getuid() != geteuid())
    fatal("This program is not intended to be setuid.\n");
  
  while ((r = getopt(argc, argv, "f:i:s:o:Q:u:NDKUqtpArlSdC")) != -1) 
#endif /* ^WIN32 */

    switch (r) {

      case 'f': config_file = optarg; break;

      case 'i': use_iface = optarg; break;

      case 's': use_dump = optarg; break;

      case 'o': if (!freopen(optarg,"a",stdout)) pfatal(optarg);
                use_logfile = 1;
                add_timestamp = 1;
                break;

#ifndef WIN32
      case 'Q': use_cache = optarg; break;
      case 'u': set_user  = optarg; break;
#endif /* !WIN32 */

      case 'r': do_resolve    = 1; break;
      case 'S': always_sig    = 1; break;
      case 'N': no_extra      = 1; break;
      case 'D': no_osdesc     = 1; break;
      case 'U': no_unknown    = 1; break;
      case 'K': no_known      = 1; break;
      case 'q': no_banner     = 1; break;
      case 'p': use_promisc   = 1; break;
      case 't': add_timestamp = 1; break;
      case 'd': go_daemon     = 1; break;
      case 'l': mode_oneline  = 1; break;
      case 'C': check_collide = 1; break;

      /* This option is intentionally sort of undocumented. It modifies p0f
         operation to analyze SYN|ACK responses instead of SYN packets.
         It is useful for silent fingerprinting over connections you have
         established, but rest assured, accuracy is decreased, and since
         some packet characteristics change, old signatures are not
         usable. */

      case 'A': use_rule = "tcp[13] & 0x17 == 0x12";
                ack_mode = 1;
                break;
#ifdef WIN32

      case 'L':
        if (pcap_findalldevs(&alldevs, ebuf) == -1)
	  fatal("pcap_findalldevs: %s\n", ebuf);

      printf("\nInterface\tDevice\t\tDescription\n"
             "-------------------------------------------\n");

      for(i=1,d=alldevs;d;d=d->next,i++) {
        debug("%d %s",i, d->name);
        if (d->description)
	  debug("\t%s",d->description);
 	debug("\n");
      }
      exit(1);
      break;

#endif  /* WIN32 */

      default: usage(argv[0]);
    }

  if (use_iface && use_dump)
    fatal("-s and -i are mutually exclusive.\n");

#ifndef WIN32
  if (!use_cache && no_known && no_unknown)
#else
  if (no_known && no_unknown)
#endif /* ^WIN32 */
    fatal("-U and -K are mutually exclusive (except with -Q).\n");

  if (!use_logfile && go_daemon)
    fatal("-d requires -o.\n");

  if (!no_banner) {
    debug("p0f - passive os fingerprinting utility, version " VER "\n"
          "(C) M. Zalewski <lcamtuf@coredump.cx>, W. Stearns <wstearns@pobox.com>\n");  
#ifdef WIN32
    debug("WIN32 version (C) Michael A. Davis <mike@datanerds.net>\n");
#endif /* WIN32 */
  }

  load_config(config_file);

  if (argv[optind] && *(argv[optind])) {
    sprintf(buf,"(%s) and (%4000s)",use_rule,argv[optind]);
    use_rule = buf;
  } 

  signal(SIGINT,&die_nicely);
  signal(SIGTERM,&die_nicely);

#ifndef WIN32
  signal(SIGHUP,&die_nicely);
  signal(SIGQUIT,&die_nicely);

  if (use_cache) {
    struct sockaddr_un x;
    
    lsock = socket(PF_UNIX,SOCK_STREAM,0);
    if (lsock < 0) pfatal("socket");

    x.sun_family = AF_UNIX;
    strncpy(x.sun_path,use_cache,63);
    unlink(use_cache);
    if (bind(lsock,(struct sockaddr*)&x,sizeof(x))) pfatal(use_cache);
    if (listen(lsock,10)) pfatal("listen");

  }

#endif /* !WIN32 */

  if (use_dump) {
    if (!(pt=pcap_open_offline(use_dump, errbuf))) 
      fatal("pcap_open_offline failed: %s\n",errbuf);
  } else {

#ifdef WIN32
    if (pcap_findalldevs(&alldevs, ebuf) == -1)
      fatal("pcap_findalldevs: %s\n", ebuf);
	
    if (!use_iface) {
      d = alldevs;
    } else {
      adapter = atoi(use_iface);
      for(i=1, d=alldevs; adapter && i < adapter && d; i++, d=d->next);
      if (!d) fatal("Unable to find adapter %d\n", adapter);
    }

    use_iface = d->name;

#else
    if (!use_iface) use_iface=pcap_lookupdev(errbuf);
#endif /* ^WIN32 */

    if (!use_iface) use_iface = "lo";

    if (!(pt=pcap_open_live(use_iface,100,use_promisc, 100,errbuf))) 
      fatal("pcap_open_live failed: %s\n",errbuf);
  }

  set_header_len(pcap_datalink(pt));

  if (pcap_compile(pt, &flt, use_rule, 1, 0))
    if (strchr(use_rule,'(')) {
      pcap_perror(pt,"pcap_compile");
      exit(1);
    }

  if (!no_banner) {
    debug("p0f: listening on '%s', %d fingerprints, rule: '%s'.\n",
          use_dump?use_dump:use_iface,sigcnt,argv[optind]?argv[optind]:"any");

#ifndef WIN32
    if (use_cache) debug("Accepting queries at socket %s.\n",use_cache);
#endif /* !WIN32 */
    
  }
  
  pcap_setfilter(pt, &flt);

#ifndef WIN32

  if (set_user) {
    struct passwd* pw;

    if (geteuid()) fatal("only root can use -u.\n");

    pw = getpwnam(set_user);
    if (!pw) fatal("user %s not found.\n",set_user);
    if (chdir(pw->pw_dir)) pfatal(pw->pw_dir);
    if (chroot(pw->pw_dir)) pfatal("chroot");
    chdir("/");

    if (initgroups(pw->pw_name,pw->pw_gid)) pfatal("initgroups");
    if (setgid(pw->pw_gid)) pfatal("setgid");
    if (setuid(pw->pw_uid)) pfatal("setuid");

    if (getegid() != pw->pw_gid || geteuid() != pw->pw_uid)
      fatal("failed to setuid/setgid to the desired UID/GID.\n");

  }

#endif /* !WIN32 */

  if (go_daemon) {

#ifndef WIN32
    _s32 f;
    fflush(0);
    f = fork();
    if (f<0) pfatal("fork() failed");
    if (f) exit(0);
    dup2(1,2);
    close(0);
    chdir("/");
    setsid();
    signal(SIGHUP,SIG_IGN);
    printf("--- p0f " VER " resuming operations at ");
    put_date();
    printf("---\n");
    fflush(0);
#else
    fatal("daemon mode is not support in the WIN32 version.\n");
#endif /* ^WIN32 */

  }

#ifndef WIN32 

  if (use_cache) {
    
    while (1) {
      fd_set f;
      static struct timeval tv; /* already zero */

      if (pcap_dispatch(pt,0,(pcap_handler)&parse,0)<0) break;

      FD_ZERO(&f);
      FD_SET(lsock,&f);

      if (select(lsock+1,&f,0,&f,&tv)>0) {
        struct p0f_query q;
        _s32 c;

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif /* ! MSG_NOSIGNAL */

        if ((c=accept(lsock,0,0))<0) continue;
        if (recv(c,&q,sizeof(q),MSG_NOSIGNAL) == sizeof(q)) 
          p0f_handlequery(c,&q);

        shutdown(c,2); 
        close(c);

      }

    }

  } else 
#endif /* !WIN32 */

  pcap_loop(pt,-1,(pcap_handler)&parse,0);

  fatal("Network is down.\n");
  return 0;

}

