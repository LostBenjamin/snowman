# CS_ARCH_MIPS, CS_MODE_32+CS_MODE_BIG_ENDIAN, None
0x7e,0x32,0x83,0x11 = precrq.qb.ph $16, $17, $18
0x7e,0x53,0x8d,0x11 = precrq.ph.w $17, $18, $19
0x7e,0x74,0x95,0x51 = precrq_rs.ph.w $18, $19, $20
0x7e,0x95,0x9b,0xd1 = precrqu_s.qb.ph $19, $20, $21
0x7c,0x15,0xa3,0x12 = preceq.w.phl $20, $21
0x7c,0x16,0xab,0x52 = preceq.w.phr $21, $22
0x7c,0x17,0xb1,0x12 = precequ.ph.qbl $22, $23
0x7c,0x18,0xb9,0x52 = precequ.ph.qbr $23, $24
0x7c,0x19,0xc1,0x92 = precequ.ph.qbla $24, $25
0x7c,0x1a,0xc9,0xd2 = precequ.ph.qbra $25, $26
0x7c,0x1b,0xd7,0x12 = preceu.ph.qbl $26, $27
0x7c,0x1c,0xdf,0x52 = preceu.ph.qbr $27, $gp
0x7c,0x1d,0xe7,0x92 = preceu.ph.qbla $gp, $sp
0x7c,0x1e,0xef,0xd2 = preceu.ph.qbra $sp, $fp
0x7f,0x19,0xbb,0x51 = precr.qb.ph $23, $24, $25
0x7f,0x38,0x07,0x91 = precr_sra.ph.w $24, $25, 0
0x7f,0x38,0xff,0x91 = precr_sra.ph.w $24, $25, 31
0x7f,0x59,0x07,0xd1 = precr_sra_r.ph.w $25, $26, 0
0x7f,0x59,0xff,0xd1 = precr_sra_r.ph.w $25, $26, 31
0x7f,0x54,0x51,0x8a = lbux $10, $20($26)
0x7f,0x75,0x59,0x0a = lhx $11, $21($27)
0x7f,0x96,0x60,0x0a = lwx $12, $22($gp)
0x00,0x43,0x18,0x18 = mult $ac3, $2, $3
0x00,0x85,0x10,0x19 = multu $ac2, $4, $5
0x70,0xc7,0x08,0x00 = madd $ac1, $6, $7
0x71,0x09,0x00,0x01 = maddu $ac0, $8, $9
0x71,0x4b,0x18,0x04 = msub $ac3, $10, $11
0x71,0x8d,0x10,0x05 = msubu $ac2, $12, $13
0x00,0x20,0x70,0x10 = mfhi $14, $ac1
0x00,0x00,0x78,0x12 = mflo $15, $ac0
0x02,0x00,0x18,0x11 = mthi $16, $ac3
0x02,0x20,0x10,0x13 = mtlo $17, $ac2
0x00,0x43,0x00,0x18 = mult $2, $3
0x00,0x85,0x00,0x19 = multu $4, $5
0x70,0xc7,0x00,0x00 = madd $6, $7
0x71,0x09,0x00,0x01 = maddu $8, $9
0x71,0x4b,0x00,0x04 = msub $10, $11
0x71,0x8d,0x00,0x05 = msubu $12, $13
0x00,0x00,0x70,0x10 = mfhi $14
0x00,0x00,0x78,0x12 = mflo $15
0x02,0x00,0x00,0x11 = mthi $16
0x02,0x20,0x00,0x13 = mtlo $17