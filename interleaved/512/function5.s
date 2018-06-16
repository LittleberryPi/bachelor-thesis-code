  .text
  .globl  nttlevel5               // -- Begin function nttlevel5
  .p2align  2
  .type  nttlevel5,@function
nttlevel5:                              // @nttlevel5
  .cfi_startproc
  // BB#0:
.Lcfi0:
  .cfi_def_cfa_offset 0
  //In the comments: U = operation with upper half of array
  //                 L = operation with lower half of array

.init:
  ldrsw  x5, [x1]                   //x5 = x1 = k out of RAM
  ptrue  p0.s                       //set the elements of P0 to true
  mov  x8, xzr                      //x8 = 0 (32 bits)
  mov  w10, #7679                   //w10 = 7679 (qinv)
  mov  z0.s, w10                    //z0 = w10 = 7679 (qinv)
  mov  w10, #7681                   //w10 = 7681 = KYBER_Q
  mov  z1.s, w10                    //z1 = w10 = 7681 = KYBER_Q
  mov  z4.h, w10                    //z4 = w10 = 7681 = KYBER_Q
  adrp x10, zetas                   //x10 = zetas address
  add  x15, x10, :lo12:zetas        //x10 = zetas group relocation
  mov  w9, #32                      //w9 = 32 = start=j+level_shift
  mov  w10, #30724                  //w10 = 30724 = 4*KYBER_Q
  mov  z3.h, w10                    //z3 = w10 = 30724 = 4*KYBER_Q
  mov  w16, #4                      //.loops condition
  mov  x14, xzr                     //counter for the loops
  mov  x10, #32
  mov  x12, xzr
  whilelo  p2.h, xzr, x16           //while 0 < x9, proceed

.loops:
  //Prepare for loop
  add  x13, x15, x5, lsl #1         //x10 = zetas[zeta_counter]
  add  w5, w5, #1                   //w5 = w9 + 1 = zeta_counter
  ld1rh  {z2.s}, p0/z, [x13]        //broadcast x10 to z2 = zeta
  mov  x8, xzr                      //x8 = 0 (32 bits)
  whilelo  p1.h, xzr, x9            //while 0 < x9, proceed

  .loop:
    add  x11, x0, x8, lsl #1          //x11 = begin address of p for iteration
    ld1h  {z5.h}, p1/z, [x11, x10, lsl #1]  //z5 = x11 + address x10 * 2 = p_high
    uunpklo  z6.s, z5.h               //z6 = lower half of z5 (p), padded with 0's
    uunpkhi  z5.s, z5.h               //z5 = upper half of z5 (p), padded with 0's
    movprfx  z7, z2                   //z7 = z2 = zeta
    mul  z7.s, p0/m, z7.s, z5.s       //z7 *= z5 (montgomery_param = zeta * pU)
    mul  z7.s, p0/m, z7.s, z0.s       //z7 *= z0 (u = montgomery_param * qinv) U
    movprfx  z16, z2                  //z16 = z2 = zeta
    mul  z16.s, p0/m, z16.s, z6.s     //z16 = z16 * z6 (montgomery_param = zeta*pL)
    and  z7.s, z7.s, #0x3ffff         //z7 = u = z7 & (1 << rlog - 1) U
    mul  z16.s, p0/m, z16.s, z0.s     //z16 = u = z16 * z0 (z16 * qinv) L
    mul  z7.s, p0/m, z7.s, z1.s       //z7 &= z1 (u *= KYBER_Q) U
    and  z16.s, z16.s, #0x3ffff       //z16 &= (1 << rlog -1) = u L
    mad  z5.s, p0/m, z2.s, z7.s       //z5 = z5 * z2 + z7 (p * zeta + u) U
    mul  z16.s, p0/m, z16.s, z1.s     //z16 *= z1 (* KYBER_Q)  L
    mad  z6.s, p0/m, z2.s, z16.s      //z6 = z6 * z2 + z16 (p * zeta + u)  L
    lsr  z6.s, z6.s, #18              //z6 = t = z6 >> 18  L
    lsr  z5.s, z5.s, #18              //z5 = t = z5 >> 18  U
    uzp1 z6.h, z6.h, z5.h             //t = concat(t L, t U)

    ld1h  {z7.h}, p1/z, [x11, x12, lsl #1]  //z7 = x0 = p_low
    sub  z5.h, z3.h, z6.h             //z5 = KYBER_Q_quadrupled_decremented
    add  z8.h, z7.h, z5.h             //z8 = barrett_param
    lsr  z9.h, z8.h, #13              //z9 = u = barrett_param >> 13
    mul z9.h, p1/m, z9.h, z4.h        //z9 = u = u * KYBER_Q
    sub z8.h, z8.h, z9.h              //z9 = barrett_param - u
    st1h  {z8.h}, p1, [x11, x10, lsl #1]      //store barrett_param in p_high

    add  z6.h, z7.h, z6.h             //z6 = barrett_param2
    lsr  z10.h, z6.h, #13             //z10 = u2 = barrett_param2 >> 13
    mul z10.h, p1/m, z10.h, z4.h      //z10 = u2 = u2 * KYBER_Q
    sub z10.h, z6.h, z10.h            //z10 = barrett_param2 - u2
    st1h  {z10.h}, p1, [x11, x12, lsl #1]     //store barrett_param2 in p_low

    inch x8                           //increment x8 with vector length
    whilelo  p1.h, x8, x9             //while x8 < x9, proceed
    b.mi  .loop                       //if x8 < x9, go back at loop

  add x10, x10, #64
  add x12, x12, #64
  add x14, x14, #1
  whilelo  p2.h, x14, x16             //while x8 < x9, proceed
  b.mi  .loops                        //if x8 < x9, go back at loop

  str  w5, [x1]                       //x1 = w5 = zeta_counter to RAM
  ret
  .cfi_endproc
