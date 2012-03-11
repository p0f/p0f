/*
   p0f - a port of lookup3
   -----------------------

   The hash32() function is a modified copy of lookup3, a good non-cryptosafe
   seeded hashing function developed by Bob Jenkins.

   Bob's original code is public domain; so is this variant.

 */

#ifndef _HAVE_HASH_H
#define _HAVE_HASH_H

#include "types.h"

#define ROL32(_x, _r) (((_x) << (_r)) | ((_x) >> (32 - (_r))))

static inline u32 hash32(const void* key, u32 len, u32 seed) {

  const u32 *k = (const u32*)key;
  u32 a, b, c;

  a = b = c = 0xdeadbeef + len + seed;

  while (len > 12) {

    a += k[0];
    b += k[1];
    c += k[2];

    a -= c; a ^= ROL32(c,  4); c += b;
    b -= a; b ^= ROL32(a,  6); a += c;
    c -= b; c ^= ROL32(b,  8); b += a;
    a -= c; a ^= ROL32(c, 16); c += b;
    b -= a; b ^= ROL32(a, 19); a += c;
    c -= b; c ^= ROL32(b,  4); b += a;

    len -= 12;
    k += 3;

  }

  switch (len) {

    case 12: c += k[2];            b += k[1]; a += k[0]; break;
    case 11: c += k[2] & 0xffffff; b += k[1]; a += k[0]; break;
    case 10: c += k[2] & 0xffff;   b += k[1]; a += k[0]; break;
    case 9:  c += k[2] & 0xff;     b += k[1]; a += k[0]; break;

    case 8:  b += k[1];            a += k[0]; break;
    case 7:  b += k[1] & 0xffffff; a += k[0]; break;
    case 6:  b += k[1] & 0xffff;   a += k[0]; break;
    case 5:  b += k[1] & 0xff;     a += k[0]; break;

    case 4:  a += k[0];            break;
    case 3:  a += k[0] & 0xffffff; break;
    case 2:  a += k[0] & 0xffff;   break;
    case 1:  a += k[0] & 0xff;     break;

    case 0:  return c;

  }

  c ^= b; c -= ROL32(b, 14);
  a ^= c; a -= ROL32(c, 11);
  b ^= a; b -= ROL32(a, 25);
  c ^= b; c -= ROL32(b, 16);
  a ^= c; a -= ROL32(c, 4);
  b ^= a; b -= ROL32(a, 14);
  c ^= b; c -= ROL32(b, 24);

  return c;

}

#endif /* !_HAVE_HASH_H */
