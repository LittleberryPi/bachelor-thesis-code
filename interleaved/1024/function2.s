  .text
  .globl  nttlevel2               // -- Begin function nttlevel2
  .p2align  2
  .type  nttlevel2,@function
nttlevel2:                              // @nttlevel2
  .cfi_startproc
.Lcfi0:
  .cfi_def_cfa_offset 0
  //In the comments: U = operation with upper half of array
  //                 L = operation with lower half of array

.init:
  ptrue   p0.s                        //set the elements of P0 to true
  mov     x8, xzr                     //x8 = 0
  mov     x15, #32                    //counter for zetas
  mov     w10, #7679                  //w10 = 7679 (qinv)
  mov     z0.s, w10                   //z0 = w10 = 7679 (qinv)
  mov     w10, #7681                  //w10 = 7681 = KYBER_Q
  mov     z1.s, w10                   //z1 = w10 = 7681 = KYBER_Q
  mov     z4.h, w10                   //z4 = w10 = 7681 = KYBER_Q
  adrp    x12, zetas                  //x10 = zetas address
  add     x12, x12, :lo12:zetas       //x10 = zetas group relocation
  mov     w9, #256                    //w9 = 256
  mov     w10, #30724                 //w10 = 30724 = 4*KYBER_Q
  mov     z3.h, w10                   //z3 = w10 = 30724 = 4*KYBER_Q
  mov     x10, #64                    //x10 = 64
  mov     x14, xzr                    //x14 = 0
  whilelo p1.h, xzr, x9               //while 0 < x9, proceed

.loop:
  //Load part of zetas
  add     x13, x12, x15, lsl #1       //address zeta for p_highL
  ld1h    {z2.h}, p1/z, [x13, x14, lsl #1]    //load zetas
  uunpklo z2.s, z2.h
  zip1    z2.s, z2.s, z2.s
  zip1    z14.s, z2.s, z2.s               //zetas for p_highL
  zip2    z2.s, z2.s, z2.s                //zetas for p_highU

  //Get array p in the right format (interleave)
  add   x11, x0, x8, lsl #1           //x11 = address of p[0]
  ld1h  {z13.h}, p1/z, [x0, x8, lsl #1]    /z13 = p1
  ld1h  {z5.h}, p1/z, [x11, x10, lsl #1]   //z5 = p2
  uzp1  z11.d, z13.d, z5.d                 //create the new p_low
  uzp2  z13.d, z13.d, z5.d                 //create the new p_high

  //Compute t
  uunpklo  z6.s, z13.h                //z6 = lower half of z5 (p_high), zero extended
  uunpkhi  z5.s, z13.h                //z5 = upper half of z5 (p_high), zero extended
  movprfx  z7, z2                     //z7 = z2 = zeta
  mul     z7.s, p0/m, z7.s, z5.s      //z7 *= z5 (montgomery_param = zeta * p_highU)
  mul     z7.s, p0/m, z7.s, z0.s      //z7 *= z0 (u = montgomery_param * qinv) U
  movprfx  z16, z14                   //z16 = z2 = zeta
  mul     z16.s, p0/m, z16.s, z6.s    //z16 = z16 * z6 (montgomery_param = zeta*p_highL)
  and     z7.s, z7.s, #0x3ffff        //z7 = u = z7 & (1 << rlog - 1) U
  mul     z16.s, p0/m, z16.s, z0.s    //z16 = u = z16 * z0 (z16 * qinv) L
  mul     z7.s, p0/m, z7.s, z1.s      //z7 &= z1 (u *= KYBER_Q) U
  and     z16.s, z16.s, #0x3ffff      //z16 &= (1 << rlog -1) = u L
  mad     z5.s, p0/m, z2.s, z7.s      //z5 = z5 * z2 + z7 (p_highU * zeta + u) U
  mul     z16.s, p0/m, z16.s, z1.s    //z16 *= z1 (* KYBER_Q)  L
  mad     z6.s, p0/m, z14.s, z16.s    //z6 = z6 * z2 + z16 (p_highL * zeta + u)
  lsr     z6.s, z6.s, #18             //z6 = t = z6 >> 18  L
  lsr     z5.s, z5.s, #18             //z5 = t = z5 >> 18  U
  uzp1    z6.h, z6.h, z5.h            //t = concat(t L, t U)

  //Compute the new p_high
  sub     z5.h, z3.h, z6.h            //z5 = KYBER_Q_quadrupled_decremented
  add     z8.h, z11.h, z5.h           //z8 = barrett_param
  lsr     z9.h, z8.h, #13             //z9 = u = barrett_param >> 13
  mul     z9.h, p1/m, z9.h, z4.h      //z8 = u = u * KYBER_Q
  sub     z8.h, z8.h, z9.h            //z8 = barrett_param - u p_high

  //Compute the new p_low
  add     z6.h, z11.h, z6.h           //z6 = barrett_param2
  lsr     z10.h, z6.h, #13            //z10 = u2 = barrett_param2 >> 13
  mul     z10.h, p1/m, z10.h, z4.h    //z10 = u2 = u2 * KYBER_Q
  sub     z10.h, z6.h, z10.h          //z10 = barrett_param2 - u2 p_low

  //Return array p to the old format
  zip1    z6.d, z10.d, z8.d           //original format of p1
  zip2    z5.d, z10.d, z8.d           //original format of p2

  //Store p_low and p_high
  st1h    {z6.h}, p1, [x0, x8, lsl #1] //store barrett_param2 in p1
  st1h    {z5.h}, p1, [x11, x10, lsl #1]  //store barrett_param in p2

  inch    x8                          //increment x8 with vector length
  inch    x8
  add     x14, x14, #16                //to load in next part of zetas
  whilelo p1.h, x8, x9                //while x8 < x9, proceed
  b.mi    .loop                       //if x8 < x9, go back to .loop
  ret
  .cfi_endproc
