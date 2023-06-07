insmod /lib/modules/5.0.4-KASLR/e1000.ko
modprobe randmod module_names=e1000 rand_period=20

insmod /lib/modules/5.0.4-KASLR/bfq.ko
modprobe randmod module_names=bfq rand_period=20
