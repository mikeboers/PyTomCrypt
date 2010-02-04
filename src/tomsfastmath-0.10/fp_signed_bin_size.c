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

int fp_signed_bin_size(fp_int *a)
{
  return 1 + fp_unsigned_bin_size (a);
}

/* $Source: /cvs/libtom/tomsfastmath/fp_signed_bin_size.c,v $ */
/* $Revision: 1.3 $ */
/* $Date: 2005/05/05 14:39:32 $ */
