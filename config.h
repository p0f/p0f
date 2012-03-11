/*

   p0f - configuration
   -------------------

   The defaults are rather sane. Be careful when changing them.

   Copyright (C) 2003 by Michal Zalewski <lcamtuf@coredump.cx>

*/

#ifndef _HAVE_CONFIG_H
#define _HAVE_CONFIG_H

#define VER		"2.0.1"

/* Paths and names to config files */

#ifdef WIN32
#  define CONFIG_DIR	"."
#else
#  define CONFIG_DIR	"/etc"
#endif /* WIN32 */

#define SYN_DB		"p0f.fp"
#define SYNACK_DB	"p0fa.fp"

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

#define MAXOPT   	15

/* Max. reasonable DNS name length */

#define MY_MAXDNS	32

/* Query cache for -S option. Increase this if your system gets lots
   of traffic and you get RESP_NOMATCH too often. */

#define QUERY_CACHE	128

/* Uncomment this to display additional information as discussed in
   p0f.fp. This functionality is a hack and will disregard options such
   as greppable output or no details mode, so do not leave it on unless,
   well, debugging. */

#undef DEBUG_EXTRAS

/* If you encounter any problems with false positives because of 
   a system with random or incremental IP ID picking a zero value once
   in a while (probability under 0.002%, but always), define this to
   disregard the 'Z' check in quirks section. */

#undef IGNORE_ZEROID

#endif /* ! _HAVE_CONFIG_H */
