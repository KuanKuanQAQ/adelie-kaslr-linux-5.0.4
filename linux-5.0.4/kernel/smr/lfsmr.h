/*
  Copyright (c) 2017, Ruslan Nikolaev
  All rights reserved.
*/

#ifndef __LFSMR_H
#define __LFSMR_H	1

#include "bits/lfsmr_cas2.h"

/* Available on all architectures. */
#define LFSMR_ALIGN	(_Alignof(struct lfsmr))
#define LFSMR_SIZE(x)		\
	((x) * sizeof(struct lfsmr_vector) + offsetof(struct lfsmr, vector))
#if LFATOMIC_BIG_WIDTH >= 2 * __LFPTR_WIDTH &&	\
		!__LFCMPXCHG_SPLIT(2 * __LFPTR_WIDTH)
__LFSMR_IMPL2(, uintptr_t, lfref_t)
#else
__LFSMR_IMPL1(, uintptr_t)
#endif

#define LFSMR32_ALIGN	(_Alignof(struct lfsmr32))
#define LFSMR32_SIZE(x)		\
	((x) * sizeof(struct lfsmr32_vector) + offsetof(struct lfsmr32, vector))
#if LFATOMIC_BIG_WIDTH >= 64 && !__LFCMPXCHG_SPLIT(64)
__LFSMR_IMPL2(32, uint32_t, uint64_t)
#else
__LFSMR_IMPL1(32, uint32_t)
#endif

/* Available on 64-bit architectures. */
#if LFATOMIC_WIDTH >= 64
# define LFSMR64_ALIGN	(_Alignof(struct lfsmr64))
# define LFSMR64_SIZE(x)		\
	((x) * sizeof(struct lfsmr64_vector) + offsetof(struct lfsmr64, vector))
# if LFATOMIC_BIG_WIDTH >= 128 && !__LFCMPXCHG_SPLIT(128)
__LFSMR_IMPL2(64, uint64_t, __uint128_t)
# else
__LFSMR_IMPL1(64, uint64_t)
# endif
#endif

#endif	/* !__LFSMR_H */

/* vi: set tabstop=4: */
