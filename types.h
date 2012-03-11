/*

   p0f - type definitions
   ----------------------
  
   Short and portable names for various integer types.

   Copyright (C) 2003-2006 by Michal Zalewski <lcamtuf@coredump.cx>

*/

#ifndef _HAVE_TYPES_H
#define _HAVE_TYPES_H

typedef unsigned char		_u8;
typedef unsigned short		_u16;
typedef unsigned int		_u32;

#ifdef WIN32
typedef unsigned __int64	_u64;
#else
typedef unsigned long long	_u64;
#endif /* ^WIN32 */

typedef signed char		_s8;
typedef signed short		_s16;
typedef signed int		_s32;

#ifdef WIN32
typedef signed __int64	_s64;
#else
typedef signed long long	_s64;
#endif /* ^WIN32 */

#endif /* ! _HAVE_TYPES_H */
