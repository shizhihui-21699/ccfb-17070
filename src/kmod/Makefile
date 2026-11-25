# SPDX-License-Identifier: GPL-2.0
# Out-of-tree module build: `make kmod KDIR=...` invokes this via the top Makefile.
obj-m += iou_uring.o
iou_uring-y := iou_kmod_main.o ../core/iou_op.o ../core/iou_version.o \
               ../core/iou_decode.o ../core/iou_rules.o ../core/iou_keeper.o
ccflags-y += -I$(src)/../../include -I$(src)/../..
