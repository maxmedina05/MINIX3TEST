/* $NetBSD: s_expm1.S,v 1.6 2010/01/06 14:11:53 phx Exp $ */

/*
 * FPLSP wrapper for expm1
 * DO NOT EDIT - this file is automatically generated.
 */

#include <machine/asm.h>

ENTRY(expm1)
#ifdef __SVR4_ABI__
	bral PIC_PLT(_C_LABEL(__fplsp060_00b0))
#else
	movel %sp@(8),%sp@-
	movel %sp@(8),%sp@-
	bsrl PIC_PLT(_C_LABEL(__fplsp060_00b0))
	fmoved %fp0,%sp@
	movel %sp@+,%d0
	movel %sp@+,%d1
	rts
#endif
