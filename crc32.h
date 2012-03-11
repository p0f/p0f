/*

   p0f - cyclic redundancy check
   -----------------------------
   
   CRC32 code. Polynomial 0x04c11db7LU.
   
   Copyright (C) 2006 by Mariusz Kozlowski <m.kozlowski@tuxland.pl>
   
 */

#ifndef _HAVE_CRC32_H
#define _HAVE_CRC32_H

_u32 crc32(_u8 *data, _u32 len);

#endif

