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
/* d = a * b (mod c) */
int fp_mulmod(fp_int *a, fp_int *b, fp_int *c, fp_int *d)
{
  fp_int tmp;
  fp_zero(&tmp);
  fp_mul(a, b, &tmp);
  return fp_mod(&tmp, c, d);
}

/* $Source: /cvs/libtom/tomsfastmath/fp_mulmod.c,v $ */
/* $Revision: 1.3 $ */
/* $Date: 2005/05/05 14:39:32 $ */
