CUR_USER=`whoami`
CUR_DEV=/dev/bus/usb/`lsusb|grep '138a:000[58]' | cut -d' ' -f2,4 | sed 's/://' |tr ' ' '/'`

# CFLAGS+="-DDEBUG"
# CFLAGS+="-DOUTPUT_RAW"
CFLAGS+="-DSTORE_SCANS"

all: access cli

access:
	@if (ls -l $(CUR_DEV) | cut -d' ' -f3|grep root); then \
		sudo chown $(CUR_USER) $(CUR_DEV); \
	fi

cli: vfs301_proto.c cli.c
	gcc $(CFLAGS) -ggdb `pkg-config --cflags libusb-1.0` -o $@ $^ `pkg-config --libs libusb-1.0`

clean: 
	rm cli

PHONY: access