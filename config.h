/*

   p0f - configuration
   -------------------

   The defaults are rather sane. Be careful when changing them.

   Copyright (C) 2003-2006 by Michal Zalewski <lcamtuf@coredump.cx>

*/

#ifndef _HAVE_CONFIG_H
#define _HAVE_CONFIG_H

#define VER		"2.0.8"

/* Paths and names to config files */

#ifdef WIN32
#  define CONFIG_DIR	"."
#else
#  define CONFIG_DIR	"/etc/p0f"
#endif /* WIN32 */

#define SYN_DB		"p0f.fp"
#define SYNACK_DB	"p0fa.fp"
#define RST_DB		"p0fr.fp"
#define OPEN_DB		"p0fo.fp"

/* Maximum number of signatures allowed in the config file */

#define MAXSIGS         1024

/* Max signature line length */

#define MAXLINE         1024

/* Maximum distance from a host to be taken seriously. Between 35 and 64
   is sane. Making it too high might result in some (very rare) false
   positives, too low will result in needless UNKNOWNs. */

#define MAXDIST         40

/* Maximum number of TCP packet options. Some systems really like to
   put lots of NOPs there. */

#define MAXOPT   	16

/* Max. reasonable DNS name length */

#define MY_MAXDNS	32

/* Query cache for -S option. This is only the default. Keep it sane -
   increase this if your system gets lots of traffic and you get RESP_NOMATCH 
   too often. */

#define DEFAULT_QUERY_CACHE	128

/* Maximum timestamp difference (hours) between two masquerade  
   signatures to be considered sane; should be reasonably high, as some
   systems might be running at higher timestamp change frequencies
   than usual. */

#define MAX_TIMEDIF	600

/* Packet dump - bytes per line; this is a sane setting. */

#define PKT_DLEN	16

/* Display no more than PKT_MAXPAY bytes of payload in -X mode. */

#define PKT_MAXPAY	45

/* Size limit for size wildcards - see p0fr.fp for more information. */

#define PACKET_BIG      100

/* Packet snap length. This is passed to libpcap, and should be never
   below 100 or such. Keep it reasonably low for performance reasons. */

#define PACKET_SNAPLEN	200

/* Query timeout on -Q socket. You must send data QUERY_TIMEOUT seconds
   after establishing a connection. Set this to zero to disable timeouts
   (not really recommended). */

#define QUERY_TIMEOUT	2

/* Uncomment this to give extra points for distance difference in
   masquerade detection. This is not recommended for Internet traffic,
   but a very good idea for looking at your local network. */

// #define DIST_EXTRASCORE

/* Uncomment this to display additional information as discussed in
   p0f.fp. This functionality is a hack and will disregard options such
   as greppable output or no details mode, so do not leave it on unless,
   well, debugging. */

// #define DEBUG_EXTRAS

/* If you encounter any problems with false positives because of 
   a system with random or incremental IP ID picking a zero value once
   in a while (probability under 0.002%, but always), uncomment this to
   disregard the 'Z' check in quirks section. */

// #define IGNORE_ZEROID


#define PID_PATH	"/var/run/p0f.pid"

#endif /* ! _HAVE_CONFIG_H */
