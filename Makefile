obj-m += fw_module.o

oall:	userfw fwmod

userfw:	userfw.c userfw.h
	gcc -Wall -o userfw userfw.c

fwmod:	
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm -f userfw firewallFile
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
