CUR_USER=`whoami`
CUR_DEV=/dev/bus/usb/`lsusb|grep '138a:000[58]' | cut -d' ' -f2,4 | sed 's/://' |tr ' ' '/'`

# CFLAGS+="-DDEBUG"
# CFLAGS+="-DOUTPUT_RAW"

all: access cli

access:
	@if (ls -l $(CUR_DEV) | cut -d' ' -f3|grep root); then \
		sudo chown $(CUR_USER) $(CUR_DEV); \
	fi

cli: vfs301_proto.c cli.c vfs301_proto_fragments.h vfs301_proto.h
	gcc $(CFLAGS) -ggdb `pkg-config --cflags libusb-1.0` -o $@ $(filter %.c %.s,$^) `pkg-config --libs libusb-1.0`

clean: 
	rm cli

PHONY: access