/*
 
  p0f - passive OS fingerprinting
  -------------------------------
  (C) Copyright 2000, 2001 by Michal Zalewski <lcamtuf@coredump.cx>
  (C) Copyright 2001 by William Stearns <wstearns@pobox.com>
  
  The p0f utility and related utilities are free software; you can
  redistribute it and/or modify it under the terms of the GNU Library
  General Public License as published by the Free Software Foundation;
  either version 2 of the License, or (at your option) any later version.
	  
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
  MICHAL ZALEWSKI, OR ANY OTHER CONTRIBUTORS BE LIABLE FOR ANY CLAIM,
  DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
  OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
  OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
			
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include <net/bpf.h>
#include <time.h>

#ifdef __MYSQL__
#include <mysql/mysql.h>
#include <mysql/mysqld_error.h>
#endif

#include "tcp.h"
#define MAXFPS 5000
#define FPBUF  150
#define INBUF  1024
#define TTLDW  30

#ifndef VER
#  define VER "(?)"
#endif /* !VER */

extern char *optarg;
extern int optind;
int fips;

char fps[MAXFPS][FPBUF];

#ifdef __MYSQL__
char mysqlstring[512];
struct fp
{
  int win;
  int ttl;
  int mss;
  int df;
  int wscale;
  int sok;
  int nop;
  int size;
  char osname[255];
};

struct mysqlconnectstring
{
  char hostname[50];
  char username[20];
  char password[20];
  char database[50];
  int port;
};

MYSQL *mysql;
MYSQL_RES *sqlres;
MYSQL_ROW sqlrow;
MYSQL_FIELD *fields;
char sqlquery[512];
struct mysqlconnectstring mconnstr;
#endif

int wss, wscale, mss, nop, ttl, df, sok,tmp,header_len=14,dupa;
u_int32_t timestamp;
char T_nounk,T_nokn,T_tstamp;
int verbose=0,sp,dp,totlen,origtot;
int usemysql = 0,generate=0;
struct in_addr sip,dip;
struct bpf_program flt;
pcap_t *pt;

#ifdef __MYSQL__
void load_mysql (char *mysqlconf) {
  FILE *fd;
  char *ptr, *token;
  if (!(fd = fopen (mysqlconf, "r"))) {
    fprintf (stderr, "Unable to open mysql configuration file");
    exit (0);
  }
  while (fgets (mysqlstring, 511, fd))
  {
    if ((ptr = strstr (mysqlstring, "mysql://")))
    {
      ptr += 8;
      if ((token = strtok (ptr, ":"))) {
              strcpy (mconnstr.hostname, token);
      }
      if ((token = strtok (NULL, ":"))) {
              strcpy (mconnstr.username, token);
      }
      if ((token = strtok (NULL, ":"))) {
              strcpy (mconnstr.password, token);
      }
      if ((token = strtok (NULL, ":"))) {
              strcpy (mconnstr.database, token);
      }
      if ((token = strtok (NULL, ":"))) {
              mconnstr.port = atoi (token);
              return;
      }
    }
  }
  fprintf(stderr,"host:%s\nuser:%s\npass:%s\n",mconnstr.hostname,mconnstr.username,mconnstr.password);
}
#endif 


void die_nicely() {
  pcap_close(pt);
#ifdef __MYSQL__
  if (usemysql)
    mysql_close(mysql);
#endif
  exit(0);
}


void lookup(void);

void set_header_len(int type){
  switch(type){
    case DLT_NULL:
#ifdef DLT_RAW
    case DLT_RAW:
#endif
    case DLT_SLIP:
      header_len=0;
      break;
    case DLT_EN10MB:
      header_len=14;
      break;
    case DLT_PPP:
#ifdef DLT_LOOP
    case DLT_LOOP:
#endif
      header_len=4;
      break;
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
      fprintf(stderr,"p0f: unknown datalink type %d.\n",type);
      break;
  }
}




void parse(u_char *blabla, struct pcap_pkthdr *pph, u_char *packet) {
  struct iphdr *iph;
  struct tcphdr *tcph;
  int ilen=0, hlen=0,off,olen;
  dupa=0;
  
  if (pph->len < header_len+sizeof(struct iphdr)+sizeof(struct tcphdr)) {
    return;
  }
  iph=(struct iphdr*)(packet+header_len);


  if ((iph->ihl>>4)!=4 || iph->protocol!=IPPROTO_TCP) {
    int a,b;
    iph=(struct iphdr*) (packet);
    // Change ihl byteorder, endian detection ;)
    a=iph->ihl&15;b=(iph->ihl>>4)&15;iph->ihl=a*16+b;
    if ((iph->ihl>>4)!=4 || iph->protocol!=IPPROTO_TCP)
      iph=(struct iphdr*)(packet+header_len);
    if ((iph->ihl>>4)!=4 || iph->protocol!=IPPROTO_TCP) {
      return;
    }
  }

  ttl=iph->ttl;
  origtot=totlen=ntohs(iph->tot_len);

  off=ntohs(iph->off);
  df=((off&IP_DF)!=0);
  sip.s_addr=iph->saddr;
  dip.s_addr=iph->daddr;
  ilen= ( (iph->ihl&0x0f) );

  switch (ilen) {
    case 5: /* no options */
      tcph=(struct tcphdr *)(iph+1);
      break;
    default: /* parse ipoptions */
      if ((header_len+(ilen<<2)+sizeof(struct tcphdr)) > pph->len) {
	return;
      }
      tcph=(struct tcphdr *)(packet+header_len+(ilen<<2));
      break;
  }

  off=tcph->th_flags;
  if (!(off&TH_SYN)) return;
  if ((off&TH_ACK)) return;

  wscale=-1;
  timestamp=-1;
  mss=0;
  nop=0;
  sok=0;

  hlen=(tcph->th_off)*4;

  {
    void* opt_ptr;
    int opt;
    opt_ptr=(void*)tcph+sizeof(struct tcphdr);
    while (dupa<hlen) {
      opt=(int)(*(u_char*)(opt_ptr+dupa));
      dupa+=1;
      switch(opt) {
        case TCPOPT_EOL:
	  dupa=100000; break; // Abandon ship!
        case TCPOPT_NOP:
  	  nop=1;
	  break;
	case TCPOPT_SACKOK:
 	  sok=1;
	  dupa++;
	  break;
	// Long options....
	case TCPOPT_MAXSEG:
	  dupa++;
  	  mss=EXTRACT_16BITS(opt_ptr+dupa);
  	  dupa+=2;
	  break;
	case TCPOPT_WSCALE:
	  olen=(int)*((char*)opt_ptr+dupa)-2; dupa++;
	  if (olen<0) olen=0;
  	  wscale=(int)*((u_char*)opt_ptr+dupa);
	  dupa+=olen;
	  break;
	case TCPOPT_TIMESTAMP:
	  olen=(int)*((char*)opt_ptr+dupa)-2; dupa++;
	  if (olen<0) olen=0;
	  timestamp= *((u_int32_t*)((void*)opt_ptr+dupa));
	  dupa+=olen;
	  break;
	default:
	  olen=(int)*((char*)opt_ptr+dupa)-2; dupa++;
	  if (olen<0) olen=0;
	  dupa+=olen;
	 break;
      }
    }
  }
#if BYTE_ORDER == LITTLE_ENDIAN
  sp=htons(tcph->th_sport);
  dp=htons(tcph->th_dport);
  wss=htons(tcph->th_win);
  timestamp=htonl(timestamp);
#else
  sp=tcph->th_sport;
  dp=tcph->th_dport;
  wss=tcph->th_win;
  /* FIXME - Big endian timestamp? */
#endif
  lookup();
  return;
}


void lookup(void) {
  int i=0,got=0,down=0,fpnum=0;
#ifdef __MYSQL__
  int r=0;
#endif
  int origw=wscale;
  char buf[INBUF],*p;
  char* plonked="\n";
plonk:
  for (down=0;down<TTLDW;down++) {
    i=0;
    sprintf(buf,"%d:%d:%d:%d:%d:%d:%d:%d",wss,ttl+down,mss,df,wscale,sok,nop,totlen);
    while (fps[i][0]) {
      if (!strncmp(buf, fps[i], strlen(buf))) {
        fpnum=fips-i;
        got=1;
        p=strrchr(fps[i],':')+1;
        if (strchr(p, '\n')) p[strlen(p)-1]=0;
        if (!T_nokn) {
          if (T_tstamp) {
            char* x;
            int i=time(0);
            x=ctime((void*)&i);
            if (x[strlen(x)-1]=='\n') x[strlen(x)-1]=0;
            printf("<%s> ",x);
          }

#ifdef __MYSQL__
          if(usemysql) {
            snprintf (sqlquery, 512,
                      "INSERT INTO pool (IP,Hops,OS,sport,dport,time) VALUES (\'%s\',%d,%d,%d,%d,NULL)",
                     inet_ntoa (sip), down + 1, fpnum, sp, dp);

            if (mysql_query (mysql, sqlquery)) {
              r = mysql_errno(mysql);
              if ( r == ER_DUP_ENTRY ) {
                snprintf(sqlquery,512,
                "UPDATE pool SET time=NULL where IP=\'%s\' and dport=%d and OS=%d",
                inet_ntoa(sip),dp, fpnum);
                mysql_query (mysql, sqlquery);
              } else {
                fprintf(stderr,"Unable to add entry: %s",mysql_error(mysql));
              }
            } else {
              sqlres = mysql_store_result (mysql);
            }
          }
#endif
          printf("%s [%d hops]: %s%s",inet_ntoa(sip),down+1,p,plonked);
    	  if (verbose) {
 	    printf(" + %s:%d ->",inet_ntoa(sip),sp);
	    printf(" %s:%d", inet_ntoa(dip),dp);
	    if (timestamp != -1)
	      printf(" (timestamp: %u @%li)",timestamp,time(NULL));
	    printf("\n");
            if (totlen==-1 && verbose) 
              printf(" * packet length for this one is %d.\n",origtot);
          }
	}
        break;
      }
      i++;
    }
    if (got) break;
  }

  if (!got) if (wscale==-1) { plonked=" *\n";wscale=0; goto plonk; }
  if (!got) if (totlen>=0) { wscale=origw; plonked=" *\n";totlen=-1; goto plonk; }

  if (!got && !T_nounk) {
    if (T_tstamp) {
      char* x;
      int i=time(0);
      x=ctime((void*)&i);
      if (x[strlen(x)-1]=='\n') x[strlen(x)-1]=0;
      printf("<%s> ",x);
    }
    printf("%s: UNKNOWN [%d:%d:%d:%d:%d:%d:%d:%d].\n",
           inet_ntoa(sip), wss, ttl, mss, df, origw, sok, nop, origtot);
    if (verbose) {
      printf(" + %s:%d ->",inet_ntoa(sip),sp);
      printf(" %s:%d", inet_ntoa(dip),dp);
      if (timestamp != -1)
        printf(" (timestamp: %u @%li)",timestamp,time(NULL));
      printf("\n");
    }
  }

  fflush(0);

}


void load_fprints(char *filename) {
  FILE *x;
  int i=0;
  char *p;
  //bzero(fips,120000);
  x=fopen(filename, "r");
  if (!x) x=fopen("p0f.fp", "r");
  if (!x) {
    fprintf(stderr, "No OS fingerprint database (%s) found. Dumb mode on.\n", 
      filename);
    return;
  }
  while (fgets(fps[i],FPBUF-1,x)) {
    if ((p=strchr(fps[i],'#')))	*p=0;
    if (fps[i][0]) {
      //fprintf(stderr,"%s",fps[i]);
      i++;
    }
  }
  fips=i;
  fclose(x);
}

#ifdef __MYSQL__
void 
load_fprints_sql(char *mysqlconf)
{
  int num_fields,i,j=0;
  load_mysql (mysqlconf);
  mysql = mysql_init (NULL);
  mysql_options (mysql, MYSQL_OPT_COMPRESS, 0);
  if (!mysql_real_connect
  (mysql, mconnstr.hostname, mconnstr.username,
   mconnstr.password, mconnstr.database, mconnstr.port,
   NULL, 0)) {
    /* we cannot connect */
    printf ("Failed to make mysql connection: %s",
    mysql_error (mysql));
    exit (1);
  }
  mysql_query(mysql,"SELECT win,ttl,mss,df,wscale,sok,nop,size,osname FROM os order by osid desc");

  sqlres = mysql_store_result(mysql);
  num_fields = mysql_num_fields(sqlres);
  while ((sqlrow = mysql_fetch_row(sqlres))) {
    for(i=0;i<num_fields-1;i++){
      strcat(fps[j],sqlrow[i]);
      strcat(fps[j],":");
    }
    strcat(fps[j],sqlrow[i]);
    strcat(fps[j],"\n");
    j++;
  };
  fips =j;
};

void 
generatefp (char *fpfile,char *mysqlconf) {
  FILE *x;
  char *ptr=0,*token=0;
  char buffer1[1024];
  struct fp myfp[MAXFPS];
  int i=0;
  load_mysql (mysqlconf);
  mysql = mysql_init (NULL);
  mysql_options (mysql, MYSQL_OPT_COMPRESS, 0);
  if (!mysql_real_connect (mysql, mconnstr.hostname, mconnstr.username, mconnstr.password, mconnstr.database, mconnstr.port, NULL, 0)) {
    /* we cannot connect */
    printf ("Failed to make mysql connection: %s", mysql_error (mysql));
    exit (1);
  }
  /* we start reading the fp file*/
  if (!(x = fopen(fpfile,"r"))) {
    fprintf(stderr,"Cannot read fp file %s.",fpfile);
    exit(1);	
  };
  /* saving the contents to the buffer structure */
  while ((ptr = fgets (buffer1, FPBUF-1, x)) != NULL) {
    //Braces needed on this next if for nesting clarity.
    if (strstr(buffer1,":"))
      if (!(strstr (buffer1, "#"))) {
        if ((token = strtok (ptr, ":"))) {
          myfp[i].win = atoi(token);
        }
        if ((token = strtok (NULL, ":"))) {
          myfp[i].ttl = atoi(token);
        }
        if ((token = strtok (NULL, ":"))) {
          myfp[i].mss = atoi(token);
        }
        if ((token = strtok (NULL, ":"))) {
          myfp[i].df = atoi(token);
        }
        if ((token = strtok (NULL, ":"))) {
          myfp[i].wscale = atoi(token);
        }
        if ((token = strtok (NULL, ":"))) {
          myfp[i].sok = atoi(token);
        }
        if ((token = strtok (NULL, ":"))) {
          myfp[i].nop = atoi(token);
        }
        if ((token = strtok (NULL, ":"))) {
          myfp[i].size = atoi(token);
        }
        if ((token = strtok (NULL, ":"))) {
          strcpy (myfp[i].osname, token);
          token = strtok(myfp[i].osname,"\n");
          strcpy(myfp[i].osname,token);
        }
        i++;
      }
  }

  /* first reset the osfp table */
  if (mysql_query(mysql,"DELETE FROM os")) {
    fprintf(stderr,"Cannot reset db. Exiting.\n");
    mysql_error(mysql);
    mysql_close(mysql);
    exit(1);
  }
    
  /* below loop inserts the fp data into sql table os */
  while(i--) {
    bzero(buffer1,512);
    sprintf(buffer1,
    "INSERT INTO os VALUES(\"\",\"%s\",%d,%d,%d,%d,%d,%d,%d,%d)",
    myfp[i].osname,myfp[i].win,myfp[i].ttl,myfp[i].mss,myfp[i].df,
    myfp[i].wscale,myfp[i].sok,myfp[i].nop,myfp[i].size);
    if (mysql_real_query(mysql,buffer1,strlen(buffer1))) {
      fprintf(stderr,"Cannot insert into db. Exiting.\n");
      mysql_error(mysql);
      mysql_close(mysql);
      exit(1);
    }
  };
};
#endif

char *ifa,*rul;

void usage(char* what) {
  fprintf(stderr,"p0f: %s\n",what);
  fprintf(stderr,"\nusage: p0f [ -f file ] [ -i device ] [ -o file ]\n"
                 "             [ -s file ] [ -vKUtq ] [ 'filter rule' ]\n");
  fprintf(stderr," -f file   read fingerprint information from file\n");
  fprintf(stderr," -i device read packets from device\n");
  fprintf(stderr," -s file   read packets from file\n");
  fprintf(stderr," -o file   write output to file (best with -vt)\n");
  fprintf(stderr," -v        verbose mode\n");
  fprintf(stderr," -U        do not display unknown signatures\n");
  fprintf(stderr," -K        do not display known signatures\n");
  fprintf(stderr," -q        be quiet (do not display banners)\n");
  fprintf(stderr," -t        add timestamps\n\n");
#ifdef __MYSQL__
  fprintf(stderr," -m file   send output to mysql server in \'file\'\n");
  fprintf(stderr," -g file   insert fprints from \'file\' into sql \n");
#endif
  exit(1);
}


int main(int argc, char *argv[]) {
  char errbuf[PCAP_ERRBUF_SIZE];
  char *filename = NULL, *inputfile = NULL;
#ifdef __MYSQL__
  char *mysqlconf = NULL;
#endif
  int r, s = 0,quiet=0;
  
#ifdef __MYSQL__
  while ((r = getopt(argc, argv, "f:i:s:m:g:vKUtqo:")) != -1) {
#else
  while ((r = getopt(argc, argv, "f:i:s:vKUtqo:")) != -1) {
#endif
    switch (r) {
      case 'f':
        filename = optarg;
	break;
      case 'q':
        quiet = 1;
	break;
      case 'i':
	ifa = optarg;
	break;
      case 's':
        s = 1;
	inputfile = optarg;
	break;
      case 'v':
        verbose = 1;
	break;
      case 'K':
        T_nokn = 1;
	break;
      case 'U':
        T_nounk = 1;
	break;
      case 't':
        T_tstamp = 1;
	break;
#ifdef __MYSQL__
      case 'm':
        usemysql=1;
        mysqlconf = optarg;
        break;
      case 'g':
        generate=1;
        filename=optarg;
        break;
#endif
      case 'o':
        if (!freopen(optarg,"a",stdout)) {
          perror(optarg);
          exit(1);
        }
	break;
      default:
	usage("Unknown option.");
    }
  }

  /* set a reasonable default fingerprint file */
  if (!filename || !*filename)
#ifdef SYSCONFDIR
    filename = SYSCONFDIR "/p0f.fp";
#else
    filename = "/etc/p0f.fp";
#endif

#ifdef __MYSQL__
  if (usemysql && !mysqlconf)
#ifdef SYSCONFDIR
    mysqlconf = SYSCONFDIR "/p0f-mysql.conf";
#else
    mysqlconf = "/etc/p0f-mysql.conf";
#endif
#endif

#ifdef __MYSQL__
  if ((!usemysql) && (generate)) {
    usage("To use -g parameter, mysql config must be set using -m parameter.");
  } else if (generate) {
    generatefp(filename,mysqlconf);
  };
#endif

  /* anything left after getopt'ing is a rule */
  if (argv[optind] && *(argv[optind]))
    rul = argv[optind];
  
  if (!ifa) ifa=pcap_lookupdev(errbuf);
  if (!ifa) { ifa="lo"; }
  
  if (!quiet)
    fprintf(stderr, "p0f: passive os fingerprinting utility, version " VER "\n"
                    "(C) Michal Zalewski <lcamtuf@gis.net>, William Stearns <wstearns@pobox.com>\n");

#ifdef __MYSQL__
  if (usemysql) {
    load_mysql (mysqlconf);
    mysql = mysql_init (NULL);
    mysql_options (mysql, MYSQL_OPT_COMPRESS, 0);
    if (!mysql_real_connect
    (mysql, mconnstr.hostname, mconnstr.username,
    mconnstr.password, mconnstr.database, mconnstr.port,
    NULL, 0)) {
      /* we cannot connect */
      printf ("Failed to make mysql connection: %s", mysql_error (mysql));
      exit (0);
    }
  }
#endif

  if (s && inputfile && *inputfile) {
    if ((pt=pcap_open_offline(inputfile, errbuf))==NULL) {
      fprintf(stderr, "pcap_open_offline failed: %s\n", errbuf);
      exit(1);
    }
  } else {
    if ((pt=pcap_open_live(ifa,100,1,100,errbuf))==NULL) {
      fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
      exit(1);
    }
  }

  set_header_len(pcap_datalink(pt));

  signal(SIGINT,&die_nicely);
  signal(SIGTERM,&die_nicely);


#ifdef __MYSQL__
  if (usemysql) {
    load_fprints_sql(mysqlconf);
  } else {
#endif
    load_fprints(filename);
#ifdef __MYSQL__
  }
#endif

  if (pcap_compile(pt, &flt, rul?rul:"", 1, 0)) {
    if (rul) {
      pcap_perror(pt,"pcap_compile");
      exit(1);
    }
  }

  if (!quiet) {    
    if (!rul) rul="all";
    fprintf(stderr,"p0f: file: '%s', %d fprints, iface: '%s', rule: '%s'.\n",filename,fips,ifa,rul);
  }

  pcap_setfilter(pt, &flt);

  pcap_loop(pt,-1,(pcap_handler)&parse,(void*)0L);
  return 0; //not reached;>
}
