/*
  Copyright (c) 2018, Ruslan Nikolaev
  All rights reserved.
*/

#ifndef __LF_C11_H
#define __LF_C11_H 1

#include <stdatomic.h>

#define LFATOMIC(x)				_Atomic(x)
#define LFATOMIC_VAR_INIT(x)	ATOMIC_VAR_INIT(x)

static inline void __lfaba_init(_Atomic(lfatomic_big_t) * obj,
		lfatomic_big_t val)
{
	atomic_init(obj, val);
}

static inline lfatomic_big_t __lfaba_load(_Atomic(lfatomic_big_t) * obj,
		memory_order order)
{
#if __LFLOAD_SPLIT(LFATOMIC_BIG_WIDTH) == 1
	lfatomic_big_t res;
	_Atomic(lfatomic_t) * hobj = (_Atomic(lfatomic_t) *) obj;
	lfatomic_t * hres = (lfatomic_t *) &res;

	hres[0] = atomic_load_explicit(hobj, order);
	hres[1] = atomic_load_explicit(hobj + 1, order);
	return res;
#elif __LFLOAD_SPLIT(LFATOMIC_BIG_WIDTH) == 0
	return atomic_load_explicit(obj, order);
#endif
}

static inline bool __lfaba_cmpxchg_weak(_Atomic(lfatomic_big_t) * obj,
	lfatomic_big_t * expected, lfatomic_big_t desired,
	memory_order succ, memory_order fail)
{
	return atomic_compare_exchange_weak_explicit(obj, expected, desired,
					succ, fail);
}

static inline bool __lfaba_cmpxchg_strong(_Atomic(lfatomic_big_t) * obj,
	lfatomic_big_t * expected, lfatomic_big_t desired,
	memory_order succ, memory_order fail)
{
	return atomic_compare_exchange_strong_explicit(obj, expected, desired,
					succ, fail);
}

#define __lfepoch_init			atomic_init
#define __lfepoch_load			atomic_load_explicit
#define __lfepoch_cmpxchg_weak	atomic_compare_exchange_weak_explicit
#define __lfepoch_fetch_add		atomic_fetch_add_explicit

#define __LFREF_CMPXCHG_FULL(dtype_t)	(1)

#define __LFREF_ATOMICS_IMPL(w, type_t, dtype_t)							\
static inline void __lfref_init##w(_Atomic(dtype_t) * obj, dtype_t val)		\
{																			\
	atomic_init(obj, val);													\
}																			\
																			\
static inline dtype_t __lfref_load##w(_Atomic(dtype_t) * obj,				\
		memory_order order)													\
{																			\
	if (!__LFLOAD_SPLIT(sizeof(dtype_t) * 8)) {								\
		return atomic_load_explicit(obj, order);							\
	} else {																\
		dtype_t res;														\
		_Atomic(type_t) * hobj = (_Atomic(type_t) *) obj;					\
		type_t * hres = (type_t *) &res;									\
																			\
		hres[0] = atomic_load_explicit(hobj, order);						\
		hres[1] = atomic_load_explicit(hobj + 1, order);					\
		return res;															\
	}																		\
}																			\
																			\
static inline type_t __lfref_link##w(_Atomic(dtype_t) * obj,				\
		memory_order order)													\
{																			\
	if (!__LFLOAD_SPLIT(sizeof(dtype_t) * 8)) {								\
		return (atomic_load_explicit(obj, order) & ~__lfref_mask##w) >>		\
					__lfrptr_shift##w;										\
	} else {																\
		_Atomic(type_t) * hobj = (_Atomic(type_t) *) obj;					\
		return atomic_load_explicit(&hobj[__LFREF_LINK], order);			\
	}																		\
}																			\
																			\
static inline bool __lfref_cmpxchgptr_weak##w(_Atomic(dtype_t) * obj,		\
		dtype_t * expected, dtype_t desired,								\
		memory_order succ, memory_order fail)								\
{																			\
	return atomic_compare_exchange_weak_explicit(obj, expected, desired,	\
			succ, fail);													\
}																			\
																			\
static inline bool __lfref_cmpxchgptr_strong##w(_Atomic(dtype_t) * obj,		\
		dtype_t * expected, dtype_t desired,								\
		memory_order succ, memory_order fail)								\
{																			\
	return atomic_compare_exchange_strong_explicit(obj, expected, desired,	\
			succ, fail);													\
}																			\
																			\
static inline bool __lfref_cmpxchgref_weak##w(_Atomic(dtype_t) * obj,		\
		dtype_t * expected, dtype_t desired,								\
		memory_order succ, memory_order fail)								\
{																			\
	return atomic_compare_exchange_weak_explicit(obj, expected, desired,	\
			succ, fail);													\
}																			\
																			\
static inline bool __lfref_cmpxchgref_strong##w(_Atomic(dtype_t) * obj,		\
		dtype_t * expected, dtype_t desired,								\
		memory_order succ, memory_order fail)								\
{																			\
	return atomic_compare_exchange_strong_explicit(obj, expected, desired,	\
			succ, fail);													\
}																			\
																			\
static inline dtype_t __lfref_fetch_add##w(_Atomic(dtype_t) * obj,			\
		dtype_t arg, memory_order order)									\
{																			\
	return atomic_fetch_add_explicit(obj, arg, order);						\
}

#endif /* !__LF_C11_H */

/* vi: set tabstop=4: */