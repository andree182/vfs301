CUR_USER=`whoami`
CUR_DEV=/dev/bus/usb/`lsusb|grep '138a:000[58]' | cut -d' ' -f2,4 | sed 's/://' |tr ' ' '/'`

all: access cli

access:
	@if (ls -l $(CUR_DEV) | cut -d' ' -f3|grep root); then \
		sudo chown $(CUR_USER) $(CUR_DEV); \
	fi

cli: proto.c cli.c
	gcc -ggdb `pkg-config --cflags libusb-1.0` `pkg-config --libs libusb-1.0` -o $@ proto.c cli.c

clean: 
	rm cli

PHONY: access