/*
  Copyright (c) 2017, Ruslan Nikolaev
  All rights reserved.
*/

#if !defined(__LFSMR_H) && !defined(__LFSMRO_H)
# error "Do not include bits/lfsmr_common.h, use lfsmr.h instead."
#endif

#include "lf.h"

#define LFSMR_NUM_CPUS 64

#define __LFSMR_COMMON_IMPL(w, type_t)										\
typedef uintptr_t lfsmr##w##_handle_t;										\
struct lfsmr##w;															\
																			\
struct lfsmr##w##_node {													\
	LFATOMIC(type_t) refs;													\
	type_t next[LFSMR_NUM_CPUS];												\
};																			\
																			\
typedef void (*lfsmr##w##_free_t) (struct lfsmr##w *,						\
		struct lfsmr##w##_node *);											\
																			\
static inline type_t __lfsmr##w##_link(struct lfsmr##w * hdr, size_t vec);	\
static inline bool __lfsmr##w##_retire(struct lfsmr##w * hdr, size_t order,	\
		type_t first, lfsmr##w##_free_t smr_free, const void * base);		\
static inline bool lfsmr##w##_enter(struct lfsmr##w * hdr, size_t vec,		\
		lfsmr##w##_handle_t * smr, const void * base, lf_check_t check);	\
static inline bool __lfsmr##w##_leave(struct lfsmr##w * hdr, size_t vec,	\
		size_t order, lfsmr##w##_handle_t smr, type_t * list,				\
		const void * base, lf_check_t check);								\
																			\
static inline struct lfsmr##w##_node * lfsmr##w##_addr(						\
	uintptr_t offset, const void * base)									\
{																			\
	return (struct lfsmr##w##_node *) ((uintptr_t) base + offset);			\
}																			\
																			\
static inline bool __lfsmr##w##_adjust_refs(struct lfsmr##w * hdr,			\
		type_t * list, type_t prev, type_t refs, const void * base)			\
{																			\
	struct lfsmr##w##_node * node;											\
	node = lfsmr##w##_addr(prev, base);										\
	if (atomic_fetch_add_explicit(&node->refs, refs,						\
							memory_order_acq_rel) == -refs) {				\
		node->next[0] = *list;												\
		*list = prev;														\
	}																		\
	return true;															\
}																			\
																			\
static inline bool __lfsmr##w##_traverse(struct lfsmr##w * hdr, size_t vec,	\
	size_t order, lfsmr##w##_handle_t * smr, type_t * list,					\
	const void * base, lf_check_t check, size_t * threshold,				\
	uintptr_t next, uintptr_t end)											\
{																			\
	struct lfsmr##w##_node * node;											\
	size_t length = 0;														\
	uintptr_t curr;															\
																			\
	do {																	\
		curr = next;														\
		if (!curr)															\
			break;															\
		node = lfsmr##w##_addr(curr, base);									\
		if (!check(hdr, node, sizeof(*node)))								\
			return false;													\
		next = node->next[vec];												\
		/* If the last reference, put into the local list. */				\
		if (atomic_fetch_sub_explicit(&node->refs, 1, memory_order_acq_rel)	\
						== 1) {												\
			node->next[0] = *list;											\
			*list = curr;													\
			if (*threshold && ++length >= *threshold) {						\
				if (!__lfsmr##w##_leave(hdr, vec, order, *smr, list, base,	\
										check))								\
					return false;											\
				*threshold = 0;												\
			}																\
		}																	\
	} while (curr != end);													\
																			\
	return true;															\
}																			\
																			\
static inline void __lfsmr##w##_free(struct lfsmr##w * hdr, type_t list,	\
	lfsmr##w##_free_t smr_free, const void * base)							\
{																			\
	struct lfsmr##w##_node * node;											\
																			\
	while (list != 0) {														\
		node = lfsmr##w##_addr(list, base);									\
		list = node->next[0];												\
		smr_free(hdr, node);												\
	}																		\
}																			\
																			\
static inline bool lfsmr##w##_leave(struct lfsmr##w * hdr, size_t vec,		\
	size_t order, lfsmr##w##_handle_t smr, lfsmr##w##_free_t smr_free,		\
	const void * base, lf_check_t check)									\
{																			\
	type_t list = 0;														\
	if (!__lfsmr##w##_leave(hdr, vec, order, smr, &list, base, check))		\
		return false;														\
	__lfsmr##w##_free(hdr, list, smr_free, base);							\
	return true;															\
}																			\
																			\
static inline bool lfsmr##w##_trim(struct lfsmr##w * hdr, size_t vec,		\
	size_t order, lfsmr##w##_handle_t * smr, lfsmr##w##_free_t smr_free,	\
	const void * base, lf_check_t check, size_t threshold)					\
{																			\
	struct lfsmr##w##_node * node;											\
	lfsmr##w##_handle_t end = *smr;											\
	size_t new_threshold = threshold;										\
	type_t link = __lfsmr##w##_link(hdr, vec);								\
	type_t list = 0;														\
																			\
	if (link != end) {														\
		*smr = link;														\
		node = lfsmr##w##_addr(link, base);									\
		if (!check(hdr, node, sizeof(*node)))								\
			return false;													\
		link = node->next[vec];													\
		if (!__lfsmr##w##_traverse(hdr, vec, order, smr, &list, base,		\
				check, &new_threshold, link, (uintptr_t) end))				\
			return false;													\
		__lfsmr##w##_free(hdr, list, smr_free, base);						\
		/* Leave was called, i.e. new_threshold = 0. */						\
		if (threshold != new_threshold)										\
			return lfsmr##w##_enter(hdr, vec, smr, base, check);			\
	}																		\
	return true;															\
}																			\
																			\
static inline bool lfsmr##w##_retire(struct lfsmr##w * hdr, size_t order,	\
		struct lfsmr##w##_node * node, lfsmr##w##_free_t smr_free,			\
		const void * base)													\
{																			\
	type_t first;															\
	first = (type_t) ((uintptr_t) node) - (type_t) ((uintptr_t) base);		\
	return __lfsmr##w##_retire(hdr, order, first, smr_free, base);			\
}

/* vi: set tabstop=4: */
