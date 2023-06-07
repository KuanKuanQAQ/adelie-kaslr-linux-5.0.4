#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/module.h>

#include <smr/smr.h>
#include "smr/lfsmr.h"

static struct workqueue_struct *smr_wq = NULL;

static union {
	_Alignas(LFSMR_ALIGN) char data[LFSMR_SIZE(SMR_NUM)];
	struct lfsmr header;
} smr;

struct SMR_Manager {
	struct work_struct my_work;
	smr_header header;
	struct module *mod;
	void *address;
};

static struct SMR_Manager * make_manager(struct module *mod, void *address)
{
	struct SMR_Manager *manager = kzalloc(sizeof(*manager), GFP_ATOMIC);
	if(!manager)
		return NULL;

	manager->mod = mod;
	manager->address = address;

	return manager;
}

static void free_manager(struct SMR_Manager *manager)
{
	kfree(manager);
}

static void unmap_work_handler(struct work_struct *work)
{
	struct SMR_Manager *manager = (struct SMR_Manager *)work;

	module_unmap(manager->mod, manager->address);
#ifdef CONFIG_X86_MODULE_RERANDOMIZE_STACK
	module_stack_empty_trash();
#endif
	free_manager(manager);
	profile_rand.count_smr_free++;
}

void smr_init(void)
{
	lfsmr_init(&smr.header, SMR_ORDER);

	if (!smr_wq)
		smr_wq = create_workqueue("smr_wq");
}

static inline void smr_do_free(struct lfsmr * h, struct lfsmr_node * node)
{
	struct SMR_Manager *manager;
	smr_header *header = (smr_header *) node;
	manager = container_of(header, struct SMR_Manager, header);

	INIT_WORK( (struct work_struct *)manager, unmap_work_handler );
	queue_work( smr_wq, (struct work_struct *)manager);
}

smr_handle smr_enter(void)
{
	size_t vec = raw_smp_processor_id() % SMR_NUM;
	smr_handle ret;
	ret.vector = vec;
	lfsmr_enter(&smr.header, vec, &ret.handle, 0, LF_DONTCHECK);
	return ret;
}

void smr_leave(smr_handle handle)
{
	lfsmr_leave(&smr.header, handle.vector, SMR_ORDER, handle.handle,
		smr_do_free, 0, LF_DONTCHECK);
}

int smr_retire(struct module *mod, void *address)
{
	struct SMR_Manager *manager = make_manager(mod, address);
	if(!manager)
		return -ENOMEM;

	profile_rand.count_smr_retire++;

	lfsmr_retire(&smr.header, SMR_ORDER, (struct lfsmr_node *)(&manager->header),
		smr_do_free, 0);

	return 0;
}


EXPORT_SYMBOL(smr_init);
EXPORT_SYMBOL(smr_enter);
EXPORT_SYMBOL(smr_leave);
EXPORT_SYMBOL(smr_retire);
