
EXTRA_CFLAGS += -v
EXTRA_CFLAGS += -fplugin=/path/to/container/dir/adelie-source/source-main/gcc-plugins/function_proepilogue_plugin.so
EXTRA_CFLAGS += -fplugin=/path/to/container/dir/adelie-source/source-main/gcc-plugins/fix_relocations_plugin.so

obj-$(CONFIG_RANDOM_TEST_DRIVER) += random_plugin_test_driver.o
EXTRA_CFLAGS += -fplugin=/path/to/container/dir/adelie-source/source-main/gcc-plugins/rerandomization_wrapper_plugin.so

clean:
	rm -rf *.ko
	rm -rf *.mod.c
	rm -rf *.o
	rm -rf *.a
	rm -rf *.order
	rm -rf *.builtin