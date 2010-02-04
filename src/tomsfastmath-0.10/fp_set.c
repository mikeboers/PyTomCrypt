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

void fp_set(fp_int *a, fp_digit b)
{
   fp_zero(a);
   a->dp[0] = b;
   a->used  = a->dp[0] ? 1 : 0;
}

/* $Source: /cvs/libtom/tomsfastmath/fp_set.c,v $ */
/* $Revision: 1.4 $ */
/* $Date: 2005/08/23 23:38:44 $ */
