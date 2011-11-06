CUR_USER=`whoami`
CUR_DEV=/dev/bus/usb/`lsusb|grep 138a:0005 | cut -d' ' -f2,4 | sed 's/://' |tr ' ' '/'`

all: access proto

access:
	@if (ls -l $(CUR_DEV) | cut -d' ' -f3|grep root); then \
		sudo chown $(CUR_USER) $(CUR_DEV); \
	fi

proto: proto.c
	gcc -ggdb `pkg-config --cflags libusb-1.0` `pkg-config --libs libusb-1.0` -o $@ $<

clean: 
	rm proto
