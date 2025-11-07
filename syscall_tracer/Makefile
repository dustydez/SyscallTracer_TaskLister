obj-m += syscall_tracer.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	sudo insmod syscall_tracer.ko

remove:
	sudo rmmod syscall_tracer

reload: remove install

info:
	modinfo syscall_tracer.ko

log:
	dmesg | tail -20
