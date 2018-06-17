  .text
  .globl  nttlevel4               // -- Begin function nttlevel4
  .p2align  2
  .type  nttlevel4,@function
nttlevel4:                              // @nttlevel4
  .cfi_startproc
.Lcfi0:
  .cfi_def_cfa_offset 0
  //In the comments: U = operation with upper half of array
  //                 L = operation with lower half of array

.init:
  ptrue   p0.s                        //set the elements of P0 to true
  mov     x8, xzr                     //x8 = 0 (32 bits)
  mov     x15, #8                     //counter for zetas
  mov     x14, xzr                    //second counter for zetas
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
  mov     x10, #128                   //x10 = 128
  whilelo p1.h, xzr, x9               //while 0 < x9, proceed

.loop:
  add     x13, x12, x15, lsl #1       //address zeta for p_highL
  ld1h    {z2.h}, p1/z, [x13, x14, lsl #1]    //load zetas
  uunpklo z2.s, z2.h
  zip1    z2.s, z2.s, z2.s
  zip1    z2.s, z2.s, z2.s
  zip1    z2.s, z2.s, z2.s
  zip1    z14.s, z2.s, z2.s           //zetas for p_highL
  zip2    z2.s, z2.s, z2.s            //zetas for p_highU

  //Get array p in the right format
  add   x11, x0, x8, lsl #1               //x11 = address of p[0]
  ld1h  {z13.h}, p1/z, [x0, x8, lsl #1]   //p1
  ld1h  {z5.h}, p1/z, [x11, x10, lsl #1]  //p2
  uunpklo z9.s, z13.h
  uunpkhi z10.s, z13.h
  uunpklo z11.s, z5.h
  uunpkhi z12.s, z5.h
  //Create a1a23a4 and b1b2b3b4
  zip1  z5.s, z9.s, z10.s             //a1'a3'a1'a3'...b1'b3'b1'b3'
  zip2  z6.s, z9.s, z10.s             //a2'a4'a2'a4'...b2'b4'b2'b4'
  //Create a1a23a4
  uunpklo z7.d, z5.s                  //a1'a3'...a1'a3'
  uunpklo z8.d, z6.s                  //a2'a4'...a2'a4'
  uzp1  z9.d, z7.d, z8.d              //a1'a2'
  uzp2  z10.d, z7.d, z8.d             //a3'a4'
  uzp1  z9.s, z9.s, z10.s             //a1'a2'a3'a4'
  //Create b1b2b3b4
  uunpkhi z7.d, z5.s                  //b1'b3'...b1'b3'
  uunpkhi z8.d, z6.s                  //b2'b4'...b2'b4'
  uzp1  z10.d, z7.d, z8.d             //b1'b2'
  uzp2  z13.d, z7.d, z8.d             //b3'b4'
  uzp1  z6.s, z10.s, z13.s            //b1'b2'b3'b4' = p_highL
  //Create c1c2c3c4 and d1d2d3d4
  zip1  z5.s, z11.s, z12.s            //c1'c3'c1'c3'...d1'd3'd1'd3'
  zip2  z10.s, z11.s, z12.s           //c2'c4'c2'c4'...d2'd4'd2'd4'
  //Create c1c2c3c4
  uunpklo z7.d, z5.s                  //c1'c3'...c1'c3'
  uunpklo z8.d, z10.s                 //c2'c4'...c2'c4'
  uzp1  z11.d, z7.d, z8.d             //c1'c2'
  uzp2  z12.d, z7.d, z8.d             //c3'c4'
  uzp1  z11.s, z11.s, z12.s           //c1'c2'c3'c4'
  //Create d1d2d3d4
  uunpkhi z7.d, z5.s                  //d1'd3'...d1'd3'
  uunpkhi z8.d, z10.s                 //d2'd4'...d2'd4'
  uzp1  z12.d, z7.d, z8.d             //d1'd2'
  uzp2  z7.d, z7.d, z8.d              //d3'd4'
  uzp1  z5.s, z12.s, z7.s             //d1'd2'd3'd4' = p_highU
  //Create a1a23a4c1c2c3c4
  uzp1  z11.h, z9.h, z11.h            //the new p_low

  //Compute t
  movprfx  z7, z2                     //z7 = z2 = zeta
  mul     z7.s, p0/m, z7.s, z5.s      //z7 *= z5 (montgomery_param = zeta * pU)
  mul     z7.s, p0/m, z7.s, z0.s      //z7 *= z0 (u = montgomery_param * qinv) U
  movprfx z16, z14                    //z16 = z2 = zeta
  mul     z16.s, p0/m, z16.s, z6.s    //z16 = z16 * z6 (montgomery_param = zeta*pL)
  and     z7.s, z7.s, #0x3ffff        //z7 = u = z7 & (1 << rlog - 1) U
  mul     z16.s, p0/m, z16.s, z0.s    //z16 = u = z16 * z0 (z16 * qinv) L
  mul     z7.s, p0/m, z7.s, z1.s      //z7 &= z1 (u *= KYBER_Q) U
  and     z16.s, z16.s, #0x3ffff      //z16 &= (1 << rlog -1) = u L
  mad     z5.s, p0/m, z2.s, z7.s      //z5 = z5 * z2 + z7 (p * zeta + u) U
  mul     z16.s, p0/m, z16.s, z1.s    //z16 *= z1 (* KYBER_Q)  L
  mad     z6.s, p0/m, z14.s, z16.s    //z6 = z6 * z2 + z16 (p * zeta + u)  L
  lsr     z6.s, z6.s, #18             //z6 = t = z6 >> 18  L
  lsr     z5.s, z5.s, #18             //z5 = t = z5 >> 18  U
  uzp1    z6.h, z6.h, z5.h            //t = concat(t L, t U)

  sub     z5.h, z3.h, z6.h            //z5 = KYBER_Q_quadrupled_decremented
  add     z8.h, z11.h, z5.h           //z8 = barrett_param
  lsr     z9.h, z8.h, #13             //z9 = u = barrett_param >> 13
  mul     z9.h, p1/m, z9.h, z4.h      //z9 = u = u * KYBER_Q
  sub     z8.h, z8.h, z9.h            //z9 = barrett_param - u p_high

  add     z6.h, z11.h, z6.h           //z6 = barrett_param2
  lsr     z10.h, z6.h, #13            //z10 = u2 = barrett_param2 >> 13
  mul     z10.h, p1/m, z10.h, z4.h    //z10 = u2 = u2 * KYBER_Q
  sub     z10.h, z6.h, z10.h          //z10 = barrett_param2 - u2 p_low

  //Return array p to the old format
  //Create a1b1a2b2a3b3a4b4 = original p1 format
  uunpklo z5.s, z10.h                 //a1'a2'a3'a4'
  uunpklo z7.d, z5.s                  //a1'a2'
  uunpkhi z11.d, z5.s                 //a3'a4'
  zip1  z9.d, z7.d, z11.d             //a1'a3'a1'a3'...a1'a3'a1'a3'
  zip2  z11.d, z7.d, z11.d            //a2'a4'a2'a4'...a2'a4'a2'a4'
  uunpklo z6.s, z8.h                  //b1'b2'b3'b4'
  uunpklo z7.d, z6.s                  //b1'b2'
  uunpkhi z6.d, z6.s                  //b3'b4'
  zip1  z13.d, z7.d, z6.d             //b1'b3'b1'b3'...b1'b3'b1'b3'
  zip2  z14.d, z7.d, z6.d             //b2'b4'b2'b4'...b2'b4'b2'b4'
  uzp1  z5.d, z9.d, z13.d             //a1'b1'
  uzp2  z6.d, z9.d, z13.d             //a3'b3'
  uzp1  z7.d, z11.d, z14.d            //a2'b2'
  uzp2  z9.d, z11.d, z14.d            //a4'b4'
  uzp1  z5.s, z5.s, z7.s              //a1'b1'a2'b2'
  uzp1  z6.s, z6.s, z9.s              //a3'b3'a4'b4'
  uzp1  z12.h, z5.h, z6.h             //a1b1a2b2a3b3a4b4 = original p1 format
  //Create c1d1c2d2c3d3c4d4 = original p2 format
  uunpkhi z5.s, z10.h                 //c1'c2'c3'c4'
  uunpklo z7.d, z5.s                  //c1'c2'
  uunpkhi z11.d, z5.s                 //c3'c4'
  zip1  z9.d, z7.d, z11.d             //c1'c3'c1'c3'...c1'c3'c1'c3'
  zip2  z11.d, z7.d, z11.d            //c2'c4'c2'c4'...c2'c4'c2'c4'
  uunpkhi z6.s, z8.h                  //d1'd2'd3'd4'
  uunpklo z7.d, z6.s                  //d1'd2'
  uunpkhi z6.d, z6.s                  //d3'd4'
  zip1  z13.d, z7.d, z6.d             //d1'd3'd1'd3'...d1'd3'd1'd3'
  zip2  z14.d, z7.d, z6.d             //d2'd4'd2'd4'...d2'd4'd2'd4'
  uzp1  z5.d, z9.d, z13.d             //c1'd1'
  uzp2  z6.d, z9.d, z13.d             //c3'd3'
  uzp1  z7.d, z11.d, z14.d            //c2'd2'
  uzp2  z9.d, z11.d, z14.d            //c4'd4'
  uzp1  z5.s, z5.s, z7.s              //c1'd1'c2'd2'
  uzp1  z6.s, z6.s, z9.s              //c3'd3'c4'd4'
  uzp1  z11.h, z5.h, z6.h             //c1d1c2d2c3d3c4d4 = original p2 format

  st1h    {z12.h}, p1, [x0, x8, lsl #1] //store barrett_param2 in p1
  st1h    {z11.h}, p1, [x11, x10, lsl #1]  //store barrett_param in p2

  inch    x8                          //increment x8 with vector length
  inch    x8
  add     x14, x14, #4
  whilelo p1.h, x8, x9                //while x8 < x9, proceed
  b.mi    .loop                       //if x8 < x9, go back to loop
  ret
  .cfi_endproc
