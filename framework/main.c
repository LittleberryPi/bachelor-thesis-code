#include <stdio.h>

#include "params.h"
#include "ntt.h"

static void naivemul(uint16_t *r, const uint16_t *a, const uint16_t *b)
{
  uint16_t t[2*KYBER_N];
  int i,j;


  /* Schoolbook multiplication of a and b, store result in t */
  for(i=0;i<2*KYBER_N;i++)
    t[i] = 0;

  for(i=0;i<KYBER_N;i++)
  {
    for(j=0;j<KYBER_N;j++)
    {
      t[i+j] += ((uint32_t)a[i] * (uint32_t)b[j]) % KYBER_Q;
      t[i+j] %= KYBER_Q;
    }
  }

  /* Reduce t modulo (X^256 + 1); store result in r */
  for(i=0;i<KYBER_N;i++)
    r[i] = (t[i] + 2*KYBER_Q - t[i+KYBER_N]) % KYBER_Q;
}



int main(void)
{
  uint16_t a[256], b[256], r1[256], r2[256];
  FILE* urandom;
  int i;

 /* Initialize a and b with random coefficients */
  urandom = fopen("/dev/urandom", "r");
  fread(a, 2, KYBER_N, urandom);
  fread(b, 2, KYBER_N, urandom);
  for(i=0;i<KYBER_N;i++)
  {
    a[i] %= KYBER_Q;
    b[i] %= KYBER_Q;
  }
  fclose(urandom);

  /* Naive multiplication */
  naivemul(r1, a, b);

  /* NTT-based multiplication */
  ntt(a);
  ntt(b);
  for(i=0;i<KYBER_N;i++)
    r2[i] = ((uint32_t)a[i] * (uint32_t)b[i]) % KYBER_Q;
  invntt(r2);


  /* Compare results of the two multiplication approaches */
  for(i=0;i<KYBER_N;i++)
    if((r1[i]-r2[i]) % KYBER_Q) printf("error at coefficient %d\n", i);

  return 0;
}
