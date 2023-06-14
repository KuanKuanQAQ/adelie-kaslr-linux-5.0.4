# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 1999 - 2006 Intel Corporation.

#
# Makefile for the Intel(R) PRO/1000 ethernet driver
#

EXTRA_CFLAGS += -fplugin=/root/adelie-kaslr-linux-5.0.4/source-main/gcc-plugins/fix_relocations_plugin.so
EXTRA_CFLAGS += -fplugin=/root/adelie-kaslr-linux-5.0.4/source-main/gcc-plugins/function_proepilogue_plugin.so
EXTRA_CFLAGS += -fplugin=/root/adelie-kaslr-linux-5.0.4/source-main/gcc-plugins/rerandomization_wrapper_plugin.so

obj-$(CONFIG_E1000) += e1000.o

e1000-objs := e1000_main.o e1000_hw.o e1000_ethtool.o e1000_param.o
