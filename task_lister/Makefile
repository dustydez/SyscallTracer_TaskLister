obj-m += task_lister.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	sudo insmod task_lister.ko

remove:
	sudo rmmod task_lister

reload: remove install

info:
	modinfo task_lister.ko

log:
	sudo dmesg | tail -20

test:
	@echo "=== Testing Task Lister Module ==="
	@echo ""
	@echo "1. Summary View:"
	@cat /proc/task_lister | head -30
	@echo ""
	@echo "2. Statistics:"
	@cat /proc/task_stats
