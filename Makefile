KERNELDIR ?= /lib/modules/$(shell uname -r)/build

obj-m := prochunter.o

PWD := $(shell pwd)

all:

	make -C $(KERNELDIR) M=$(PWD) modules

clean:

	rm -fr *.o *.mod.c *.order Module.symvers .prochunter* .tmp_*

