#pragma once

#define SMR_ORDER	6U /* 64 CPUs */
#define SMR_NUM		(1U << SMR_ORDER)

typedef struct _smr_header {
	void *reserved[SMR_NUM+1];
} smr_header;

typedef struct _smr_handle {
	unsigned long handle;
	unsigned long vector;
} smr_handle;

void smr_init(void);
smr_handle smr_enter(void);
void smr_leave(smr_handle);
int smr_retire(struct module *mod, void *address);
