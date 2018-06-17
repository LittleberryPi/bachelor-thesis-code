  .text
  .file    "function.c"
  .globl    nttlevel7               // -- Begin function nttlevel7
  .p2align    2
  .type    nttlevel7,@function
nttlevel7:                              // @nttlevel7
  .cfi_startproc
  // BB#0:
.Lcfi0:
  .cfi_def_cfa_offset 0
  //In the comments: U = operation with upper half of array
  //                 L = operation with lower half of array
  ldrsw    x9, [x1]                        //x9 = x1 = k out of RAM
  ptrue    p0.s                            //set the elements of P0 to true
  mov    x8, xzr                           //x8 = 0 (32 bits)
  add    w10, w9, #1             // =1     //w10 = w9 + 1 = zeta_counter
  str    w10, [x1]                         //x1 = w10 = zeta_counter to RAM
  mov    w10, #7679                        //w10 = 7679 (qinv)
  mov    z0.s, w10                         //z0 = w10 = 7679 (qinv)
  mov    w10, #7681                        //w10 = 7681 = KYBER_Q
  mov    z1.s, w10                         //z1 = w10 = 7681 = KYBER_Q
  adrp    x10, zetas                       //x10 = zetas address
  add    x10, x10, :lo12:zetas             //x10 = zetas group relocation
  add    x10, x10, x9, lsl #1              //x10 = zetas[zeta_counter]
  ld1rh    {z2.s}, p0/z, [x10]             //broadcast x10 to z2 = zeta
  mov    w10, #30724                       //w10 = 30724 = 4*KYBER_Q
  orr    w9, xzr, #0x80                    //w9 = 128 = level_shift
  mov    z3.s, w10                         //z3 = w10 = 30724 = 4*KYBER_Q
  orr    w10, xzr, #0xffffe1ff             //w10 = #0xffffe1ff = -KYBER_Q
  whilelo    p1.h, xzr, x9                 //while 0 < x9, proceed
  mov    z4.s, w10                         //z4 = w10 = #0xffffe1ff = -KYBER_Q
  orr    x10, xzr, #0x80                   //x10 = 128 (half size(p))
.LBB0_1:
  add    x11, x0, x8, lsl #1               //x11 = address of p[127]
  ld1h    {z5.h}, p1/z, [x11, x10, lsl #1]//z5 = x11 + address x10 * 2 = p
  uunpklo    z6.s, z5.h              //z6 = lower half of z5 (p), padded with 0's
  uunpkhi    z5.s, z5.h              //z5 = upper half of z5 (p), padded with 0's
  movprfx    z7, z2                  //z7 = z2 = zeta
  mul    z7.s, p0/m, z7.s, z5.s      //z7 *= z5 (montgomery_param = zeta * pU)
  mul    z7.s, p0/m, z7.s, z0.s      //z7 *= z0 (u = montgomery_param * qinv) U
  movprfx    z16, z2                 //z16 = z2 = zeta
  mul    z16.s, p0/m, z16.s, z6.s    //z16 = z16 * z6 (montgomery_param = zeta*pL
  and    z7.s, z7.s, #0x3ffff        //z7 = u = z7 & (1 << rlog - 1) U
  mul    z16.s, p0/m, z16.s, z0.s    //z16 = u = z16 * z0 (z16 * qinv) L
  mul    z7.s, p0/m, z7.s, z1.s            //z7 &= z1 (u *= KYBER_Q) U
  and    z16.s, z16.s, #0x3ffff            //z16 &= (1 << rlog -1) = u L
  mad    z5.s, p0/m, z2.s, z7.s            //z5 = z5 * z2 + z7 (p * zeta + u) U
  ld1h    {z7.h}, p1/z, [x0, x8, lsl #1]   //z7 = x0 = p_value
  mul    z16.s, p0/m, z16.s, z1.s          //z16 *= z1 (* KYBER_Q) L
  mad    z6.s, p0/m, z2.s, z16.s           //z6 = z6 * z2 + z16 (p * zeta + u) L
  lsr    z6.s, z6.s, #18                   //z6 = t = z6 >> 18    L
  lsr    z5.s, z5.s, #18                   //z5 = t = z5 >> 18    U
  sub    z16.s, z3.s, z5.s          //z16=KYBER_Q_quadrupled_decremented = z3-z5 U
  sub    z17.s, z3.s, z6.s          //z17=KYBER_Q_quadrupled_decremented = z3-z6 L
  uunpkhi    z18.s, z7.h                   //z18 = upper half of z7(p)
  uunpklo    z7.s, z7.h                    //z7 = lower half of z7 (p)
  add    z17.s, z17.s, z7.s                //z17 += z7 = barrett_param L
  add    z16.s, z16.s, z18.s               //z16 += z18 = barrett_param U
  add    z6.s, z6.s, z7.s                  //z6 += z7 = barrett_param2 L
  add    z5.s, z5.s, z18.s                 //z5 += z18 = barrett_param2 U
  lsr    z7.s, z16.s, #13                  //z7 = u = barrett_param >> 13 U
  lsr    z18.s, z17.s, #13                 //z18 = u = barrett_param > 13 L
  lsr    z19.s, z5.s, #13                  //z19 = u = barrett_param2 >> 13 U
  lsr    z20.s, z6.s, #13                  //z20 = u = barrett_param2 >> 13 L

  //u *= KYBER_Q and barrett_param -= u
  //u2 *= KYBER_Q and barrett_param2 -= u2
  and    z18.s, z18.s, #0x7                //z18 &= 7
  and    z7.s, z7.s, #0x7                  //z7 &= 7
  and    z20.s, z20.s, #0x7                //z20 &= 7
  and    z19.s, z19.s, #0x7                //z19 &= 7
  mad    z7.s, p0/m, z4.s, z16.s           //z7 = z7 * z4 + z16
  movprfx    z16, z17                      //z16 = z17 = barrett_param L
  mla    z16.s, p0/m, z18.s, z4.s          //z16 = z16 + z18 * z4
  mla    z5.s, p0/m, z19.s, z4.s           //z5 = z5 + z19 * z4
  mla    z6.s, p0/m, z20.s, z4.s           //z6 = z6 + z20 * z4

  uzp1    z7.h, z16.h, z7.h        //z7 = concat(barrett_param U, barrett_param L)
  uzp1    z5.h, z6.h, z5.h         //z5 = concat(barrett_param2 U,barrett_param2 L)
  st1h    {z7.h}, p1, [x11, x10, lsl #1]   //store barrett_param in p[i >= 128]
  st1h    {z5.h}, p1, [x0, x8, lsl #1]     //store barrett_param2 in p
  inch    x8                  //increment x8 with Vector length
  whilelo    p1.h, x8, x9                  //while x8 < x9, proceed
  b.mi    .LBB0_1                          //if x8 < x9, go back to loop
  // BB#2:
  ret
  .Lfunc_end0:
  .size    nttlevel7, .Lfunc_end0-nttlevel7
  .cfi_endproc
  // -- End function

  .ident    "Arm C/C++/Fortran Compiler version 18.0 (build number 33) (based on LLVM 5.0.1)"
  .section    ".note.GNU-stack","",@progbits
