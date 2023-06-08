# manual 分支
1. 以手动修改的方式为 bfq、e1000 等内核模块增加重随机功能。
2. 追加函数指针测试。

## 注意：
1. fuse 模块补丁疑似 bug。kaslr_fuse.patch 会导致编译失败。所以本分支未应用 kaslr_fuse.patch.
2. 宏 TRACE_FLF 支持打印 file name、line num 和 func name。

## bfq wrapper list:
### struct
SPECIAL_CONST_VAR

SPECIAL_VAR
* blkcg_policy_bfq

in `struct blkcg_policy blkcg_policy_bfq`:
* bfq_blkg_files
* bfq_blkcg_legacy_files

* iosched_bfq_mq

in `struct elevator_type iosched_bfq_mq`:
* bfq_attrs
### function
> static 函数仍然需要 SPECIAL_FUNCTION？

in `struct blkcg_policy blkcg_policy_bfq`:
* bfq_cpd_alloc
* bfq_cpd_init
* bfq_cpd_free
* bfq_pd_alloc
* bfq_pd_init
* bfq_pd_offline
* bfq_pd_free
* bfq_pd_reset_stat

in `struct elevator_type iosched_bfq_mq`:
* bfq_limit_depth
* bfq_prepare_request
* bfq_finish_requeue_request
* bfq_exit_icq
* bfq_insert_requests
* bfq_dispatch_request
* elv_rb_latter_request
* elv_rb_former_request
* bfq_allow_bio_merge
* bfq_bio_merge
* bfq_request_merge
* bfq_requests_merged
* bfq_request_merged
* bfq_has_work
* bfq_init_hctx
* bfq_init_queue
* bfq_exit_queue
