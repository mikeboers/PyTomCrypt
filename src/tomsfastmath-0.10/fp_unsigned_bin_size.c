/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include <tfm.h>

int fp_unsigned_bin_size(fp_int *a)
{
  int     size = fp_count_bits (a);
  return (size / 8 + ((size & 7) != 0 ? 1 : 0));
}

/* $Source: /cvs/libtom/tomsfastmath/fp_unsigned_bin_size.c,v $ */
/* $Revision: 1.3 $ */
/* $Date: 2005/05/05 14:39:32 $ */
