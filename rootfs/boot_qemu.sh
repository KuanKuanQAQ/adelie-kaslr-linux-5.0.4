sh mkrootfs.sh
qemu-system-x86_64 -s\
    -kernel ../linux-5.0.4/arch/x86_64/boot/bzImage \
    -initrd ./initramfs.cpio.gz \
    -nographic \
    -append "nokaslr console=ttyS0"

    #-net socket,connect=127.0.0.1:1235 \

#    -append "nokaslr console=ttyS0"
