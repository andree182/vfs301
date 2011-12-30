/*
 * vfs301 fingerprint driver 
 * 
 * Copyright (c) 2011 Andrej Krutak <dev@andree.sk>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <libusb-1.0/libusb.h>

#include "vfs301_proto.h"
#include <unistd.h>

#define min(a, b) (((a) < (b)) ? (a) : (b))

/************************** USB STUFF *****************************************/

/* init state of the usb subsystem */
static enum {
	STATE_NOTHING,
	STATE_INIT,
	STATE_OPEN,
	STATE_CLAIMED,
	STATE_CONFIGURED
} state;

/* context object for libusb library */
static struct libusb_context *ctx;
static struct libusb_device_handle *devh;

static uint16_t usb_ids_supported[][2] = {
	{0x138a, 0x0008}, /* vfs300 */
	{0x138a, 0x0005}, /* vfs301 */
};

static void usb_init(void)
{
	int i;
	int r;
	
	assert(state == STATE_NOTHING);
	
	r = libusb_init(&ctx);
	if (r != 0) {
		fprintf(stderr, "Failed to initialise libusb\n");
		return;
	}
	state = STATE_INIT;

	for (i = 0; i < sizeof(usb_ids_supported) / sizeof(usb_ids_supported[0]); i++) {
		devh = libusb_open_device_with_vid_pid(
			NULL, usb_ids_supported[i][0], usb_ids_supported[i][1]
		);
		if (devh != NULL)
			break;
	}
	if (devh == NULL) {
		fprintf(stderr, "Can't open any validity device!\n");
		return;
	}
	state = STATE_OPEN;

	for (i = 0; i < 1000000; i++){
		r = libusb_kernel_driver_active(devh, i);
		if (r == 1) {
			r = libusb_detach_kernel_driver(devh, 4);
			if (r < 0)
				fprintf(stderr, "Error detaching kernel driver!\n");
		}
	}

	r = libusb_claim_interface(devh, 0);
	if (r != 0) {
		fprintf(stderr, "usb_claim_interface error %d\n", r);
		return;
	}
	state = STATE_CLAIMED;

	r = libusb_reset_device(devh);
	if (r != 0) {
		fprintf(stderr, "Error resetting device");
		return;
	}

	r = libusb_control_transfer(
		devh, LIBUSB_REQUEST_TYPE_STANDARD, LIBUSB_REQUEST_SET_FEATURE, 
		1, 1, NULL, 0, VFS301_DEFAULT_WAIT_TIMEOUT
	); 
	if (r != 0) {
		fprintf(stderr, "device configuring error %d\n", r);
		return;
	}
	state = STATE_CONFIGURED;
}

static void usb_deinit(void)
{
	int r;

	if (state == STATE_CONFIGURED) {
		r = libusb_reset_device(devh); 
		if (r != 0)
			fprintf(stderr, "Failed to reset device\n");
		state = STATE_CLAIMED;
	}

	if (state == STATE_CLAIMED) {
		r = libusb_release_interface(devh, 0);
		if (r != 0)
			fprintf(stderr, "Failed to release interface (%d)\n", r);
		state = STATE_OPEN;
	}

	if (state == STATE_OPEN) {
		libusb_close(devh);
		devh = NULL;
		state = STATE_INIT;
	}

	if (state == STATE_INIT) {
		libusb_exit(ctx);
		ctx = NULL;
		state = STATE_NOTHING;
	}
}

/******************************* OUTPUT ***************************************/

static void img_store(vfs301_dev_t *dev)
{
	static int idx = 0;
	char fn[32];
	FILE *f;
	unsigned char *img;
	int height;
	
	img = malloc(dev->scanline_count * VFS301_FP_OUTPUT_WIDTH);
	
	vfs301_extract_image(dev, img, &height);
	
	if (height > 20) {
		sprintf(fn, "scan_%02d.pgm", idx++);
		
		f = fopen(fn, "wb");
		assert(f != NULL);
		
		fprintf(f, "P5\n%d %d\n255\n", VFS301_FP_OUTPUT_WIDTH, height);
		fwrite(img, height * VFS301_FP_OUTPUT_WIDTH, 1, f);
		fclose(f);
	} else {
		fprintf(stderr, 
			"fingerprint too short (%dx%d px), ignoring...\n", 
			VFS301_FP_WIDTH, height
		);
	}
	
	free(img);
}

/************************** GENERIC STUFF *************************************/

static vfs301_dev_t dev;

static void init(vfs301_dev_t *dev)
{
	state = STATE_NOTHING;
	dev->scanline_buf = malloc(0);
	dev->scanline_count = 0;
	
	usb_init();
	if (state == STATE_CONFIGURED)
		vfs301_proto_init(devh, dev);
}

static void work(vfs301_dev_t *dev)
{
	while (1) {
		fprintf(stderr, "waiting for next fingerprint...\n");
		vfs301_proto_request_fingerprint(devh, dev);
		while (!vfs301_proto_peek_event(devh, dev))
			usleep(200000);
		
		fprintf(stderr, "reading fingerprint...\n");
		vfs301_proto_process_event(devh, dev);
		
		img_store(dev);
	}
}

static void deinit(vfs301_dev_t *dev)
{
	vfs301_proto_deinit(devh, dev);
	usb_deinit();
	
	free(dev->scanline_buf);
}

static void handle_signal(int sig)
{
	(void)sig;
	
	fprintf(stderr, "That was all, folks\n");
	deinit(&dev);
}

int main(int argc, char **argv)
{
	signal(SIGINT, handle_signal);
	state = STATE_NOTHING;
	
	init(&dev);
	
	if (state == STATE_CONFIGURED)
		work(&dev);
	
	if (state != STATE_NOTHING)
		deinit(&dev);
}
