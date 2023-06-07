cp ../linux-5.0.4/drivers/net/ethernet/intel/e1000/e1000.ko ./initramfs/lib/modules/5.0.4-KASLR/
cp ../linux-5.0.4/drivers/net/ethernet/intel/e1000e/e1000e.ko ./initramfs/lib/modules/5.0.4-KASLR/
cp ../linux-5.0.4/block/bfq/bfq.ko ./initramfs/lib/modules/5.0.4-KASLR/

cp ~/linux-5.0.4/kernel/randmod.ko ./initramfs/lib/modules/5.0.4-KASLR/

cd ./initramfs/
find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
