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

/* c = a mod b, 0 <= c < b  */
int fp_mod_d(fp_int *a, fp_digit b, fp_digit *c)
{
   return fp_div_d(a, b, NULL, c);
}

/* $Source: /cvs/libtom/tomsfastmath/fp_mod_d.c,v $ */
/* $Revision: 1.3 $ */
/* $Date: 2005/05/05 14:39:32 $ */
