ifneq ($(KERNELRELEASE),)
	mymodule-objs:=vtun.o
	obj-m:=vtun.o
else
	PWD:=$(shell pwd)
	KVER:=$(shell uname -r)
	KDIR:=/usr/src/linux-headers-3.19.0-rc6-zhuyj
all:
	$(MAKE) -C $(KDIR) M=$(PWD)
install:
	insmod ./vtun.ko
remove:
	rmmod vtun.ko
clean:
	@rm -rf .*.com *.o *.mod.c *.ko .tmp_versions modules.order Module.symvers
endif
