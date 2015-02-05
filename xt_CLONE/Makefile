ifneq ($(KERNELRELEASE),)
	mymodule-objs:=xt_CLONE.o
	obj-m:=xt_CLONE.o
else
	PWD:=$(shell pwd)
	KVER:=$(shell uname -r)
	KDIR:=/usr/src/linux-headers-3.19.0-rc6-zhuyj
all:
	$(MAKE) -C $(KDIR) M=$(PWD)
install:
	insmod ./xt_CLONE.ko
remove:
	rmmod xt_CLONE.ko
clean:
	@rm -rf .*.com *.o *.mod.c *.ko .tmp_versions modules.order Module.symvers
endif
