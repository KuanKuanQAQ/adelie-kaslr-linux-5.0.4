这里是 manual 分支：
1. 以手动修改的方式为 bfq、e1000 等内核模块增加重随机功能。
2. 追加函数指针测试。

注意：
1. fuse 模块补丁疑似 bug。kaslr_fuse.patch 会导致编译失败。
