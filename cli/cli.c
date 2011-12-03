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

static uint16_t usb_ids_supported[][2] = {
	{0x138a, 0x0008}, /* vfs300 */
	{0x138a, 0x0005}, /* vfs301 */
};

static void usb_init(vfs_dev_t *dev)
{
	int i;
	int r;
	
	assert(dev->state == STATE_NOTHING);
	
	r = libusb_init(&dev->ctx);
	if (r != 0) {
		fprintf(stderr, "Failed to initialise libusb\n");
		return;
	}
	dev->state = STATE_INIT;

	for (i = 0; i < sizeof(usb_ids_supported) / sizeof(usb_ids_supported[0]); i++) {
		dev->devh = libusb_open_device_with_vid_pid(
			NULL, usb_ids_supported[i][0], usb_ids_supported[i][1]
		);
		if (dev->devh != NULL)
			break;
	}
	if (dev->devh == NULL) {
		fprintf(stderr, "Can't open any validity device!\n");
		return;
	}
	dev->state = STATE_OPEN;

	for (i = 0; i < 1000000; i++){
		r = libusb_kernel_driver_active(dev->devh, i);
		if (r == 1) {
			r = libusb_detach_kernel_driver(dev->devh, 4);
			if (r < 0)
				fprintf(stderr, "Error detaching kernel driver!\n");
		}
	}

	r = libusb_claim_interface(dev->devh, 0);
	if (r != 0) {
		fprintf(stderr, "usb_claim_interface error %d\n", r);
		return;
	}
	dev->state = STATE_CLAIMED;

	r = libusb_reset_device(dev->devh);
	if (r != 0) {
		fprintf(stderr, "Error resetting device");
		return;
	}

	r = libusb_control_transfer(
		dev->devh, LIBUSB_REQUEST_TYPE_STANDARD, LIBUSB_REQUEST_SET_FEATURE, 
		1, 1, NULL, 0, VALIDITY_DEFAULT_WAIT_TIMEOUT
	); 
	if (r != 0) {
		fprintf(stderr, "device configuring error %d\n", r);
		return;
	}
	dev->state = STATE_CONFIGURED;
}

static void usb_deinit(vfs_dev_t *dev)
{
	int r;

	if (dev->state == STATE_CONFIGURED) {
		r = libusb_reset_device(dev->devh); 
		if (r != 0)
			fprintf(stderr, "Failed to reset device\n");
		dev->state = STATE_CLAIMED;
	}

	if (dev->state == STATE_CLAIMED) {
		r = libusb_release_interface(dev->devh, 0);
		if (r != 0)
			fprintf(stderr, "Failed to release interface (%d)\n", r);
		dev->state = STATE_OPEN;
	}

	if (dev->state == STATE_OPEN) {
		libusb_close(dev->devh);
		dev->devh = NULL;
		dev->state = STATE_INIT;
	}

	if (dev->state == STATE_INIT) {
		libusb_exit(dev->ctx);
		dev->ctx = NULL;
		dev->state = STATE_NOTHING;
	}
}

static void usb_print_packet(int dir, int rv, const unsigned char *data, int length) 
{
	int i;

#ifdef DEBUG
	fprintf(stderr, "%s, rv %d, len %d\n", dir ? "send" : "recv", rv, length);
#endif
	
#ifdef PRINT_VERBOSE
	for (i = 0; i < min(length, 128); i++) {
		fprintf(stderr, "%.2X ", data[i]);
		if (i % 8 == 7)
			fprintf(stderr, " ");
		if (i % 32 == 31)
			fprintf(stderr, "\n");
	}
#endif

	fprintf(stderr, "\n");
}


int usb_recv(vfs_dev_t *dev, unsigned char endpoint, int max_bytes)
{
	int transferred = 0;
	
	assert(max_bytes <= sizeof(dev->recv_buf));
	
	int r = libusb_bulk_transfer(
		dev->devh, endpoint, 
		dev->recv_buf, max_bytes,
		&dev->recv_len, VALIDITY_DEFAULT_WAIT_TIMEOUT
	);
	
#ifdef DEBUG
	usb_print_packet(0, r, dev->recv_buf, dev->recv_len);
#endif
	
	if (r < 0)
		return r;
	return 0;
}

int usb_send(vfs_dev_t *dev, const unsigned char *data, int length)
{
	int transferred = 0;
	
	int r = libusb_bulk_transfer(
		dev->devh, VALIDITY_SEND_ENDPOINT, 
		(unsigned char *)data, length, &transferred, VALIDITY_DEFAULT_WAIT_TIMEOUT
	);

#ifdef DEBUG
	usb_print_packet(1, r, data, length);
#endif
	
	assert(r == 0);
	
	if (r < 0)
		return r;
	if (transferred < length)
		return r;
	
	return 0;
}

/************************** GENERIC STUFF *************************************/


static vfs_dev_t dev;

static void init(vfs_dev_t *dev)
{
	dev->state = STATE_NOTHING;
	dev->scanline_buf = malloc(0);
	dev->scanline_count = 0;
	
	usb_init(dev);
	proto_init(dev);
}

static void work(vfs_dev_t *dev)
{
}

static void deinit(vfs_dev_t *dev)
{
	proto_deinit(dev);
	usb_deinit(dev);
	
	free(dev->scanline_buf);
}

static void handle_signal(int sig)
{
	(void)sig;
	
	fprintf(stderr, "That was all, folks\n");
	deinit(&dev);
}

int main (int argc, char **argv)
{
	signal(SIGINT, handle_signal);
	
	init(&dev);
	
	if (dev.state == STATE_CONFIGURED)
		work(&dev);
	
	if (dev.state != STATE_NOTHING)
		deinit(&dev);
}
