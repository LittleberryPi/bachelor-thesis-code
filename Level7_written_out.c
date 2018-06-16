void nttlevel7(uint16_t *p, int *k){
  int level, j, p_counter;
  uint16_t zeta, t, p_high, p_low, KYBER_Q_quadrupled_decremented,
  barrett_param, barrett_param2;
  uint32_t zeta_uint32, montgomery_param, u, u2;

  level = 7;
  int zeta_counter = (*k)++;
  zeta = zetas[zeta_counter];
  int level_shift = 1 << level;

  for(j = 0; j < level_shift; ++j){
    //initialize the parameter for montgomery_reduce()
    zeta_uint32 = (uint32_t)zeta;
    p_counter = j + level_shift;
    p_high = p[p_counter];
    montgomery_param = zeta_uint32 * p_high;
    //t = montgomery_reduce((uint32_t)zeta * p[j + (1<<level)]);
    u = montgomery_param * qinv;
    u &= (1 << rlog) - 1;
    u *= KYBER_Q;
    montgomery_param += u;
    t = montgomery_param >> rlog;

    //initialize parameter for the first barrett_reduce()
    p_low = p[j];
    KYBER_Q_quadrupled_decremented = 4*KYBER_Q - t;
    barrett_param = p_low + KYBER_Q_quadrupled_decremented;
    //p[j + (1<<level)] = barrett_reduce(p[j] + 4*KYBER_Q - t);
    u = barrett_param >> 13; //((uint32_t) a * sinv) >> 16;
    u *= KYBER_Q;
    barrett_param -= u;
    p[p_counter] = barrett_param;

    //initialize parameter for the second barrett_reduce()
    barrett_param2 = p_low + t;
    //p[j] = barrett_reduce(p[j] + t);
    u2 = barrett_param2 >> 13;//((uint32_t) a * sinv) >> 16;
    u2 *= KYBER_Q;
    barrett_param2 -= u2;
    p[j] = 	barrett_param2;
  }
}
