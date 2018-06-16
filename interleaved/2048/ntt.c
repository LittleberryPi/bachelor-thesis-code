#include "inttypes.h"
#include "ntt.h"
#include "params.h"
#include "reduce.h"
#include "function7.h"
#include "function6.h"
#include "function5.h"
#include "function4.h"
#include "function3.h"
#include "function2.h"
#include "function1.h"
#include "function0.h"
#include <stdio.h>
#include <stdlib.h>

extern const uint16_t omegas_inv_bitrev_montgomery[];
extern const uint16_t psis_inv_montgomery[];
extern const uint16_t zetas[];

/*************************************************
* Name:        ntt
*
* Description: Computes negacyclic number-theoretic transform (NTT) of
*              a polynomial (vector of 256 coefficients) in place;
*              inputs assumed to be in normal order, output in bitreversed order
*
* Arguments:   - uint16_t *p: pointer to in/output polynomial
**************************************************/

void ntt(uint16_t *p)
{
  int k = 1;
  nttlevel7(p, &k);
  nttlevel6(p);
  nttlevel5(p);
  nttlevel4(p);
  nttlevel3(p);
  nttlevel2(p);
  nttlevel1(p);
  nttlevel0(p);
}

/*************************************************
* Name:        invntt
*
* Description: Computes inverse of negacyclic number-theoretic transform (NTT) of
*              a polynomial (vector of 256 coefficients) in place;
*              inputs assumed to be in bitreversed order, output in normal order
*
* Arguments:   - uint16_t *a: pointer to in/output polynomial
**************************************************/
void invntt(uint16_t * a)
{
  int start, j, jTwiddle, level;
  uint16_t temp, W;
  uint32_t t;

  for(level=0;level<8;level++)
  {
    for(start = 0; start < (1<<level);start++)
    {
      jTwiddle = 0;
      for(j=start;j<KYBER_N-1;j+=2*(1<<level))
      {
        W = omegas_inv_bitrev_montgomery[jTwiddle++];
        temp = a[j];

        if(level & 1) /* odd level */
          a[j] = barrett_reduce((temp + a[j + (1<<level)]));
        else
          a[j] = (temp + a[j + (1<<level)]); /* Omit reduction (be lazy) */

        t = (W * ((uint32_t)temp + 4*KYBER_Q - a[j + (1<<level)]));

        a[j + (1<<level)] = montgomery_reduce(t);
      }
    }
  }

  for(j = 0; j < KYBER_N; j++)
    a[j] = montgomery_reduce((a[j] * psis_inv_montgomery[j]));
}
