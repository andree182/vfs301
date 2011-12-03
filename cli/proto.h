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

enum {
	VALIDITY_DEFAULT_WAIT_TIMEOUT = 300,
	
	VALIDITY_SEND_ENDPOINT = 0x01,
	VALIDITY_RECEIVE_ENDPOINT_CTRL = 0x81,
	VALIDITY_RECEIVE_ENDPOINT_DATA = 0x82
};

typedef struct {
	/* context object for libusb library */
	struct libusb_context *ctx;

	/* libusb device handle for fingerprint reader */
	struct libusb_device_handle *devh;

	/* init state of the usb subsystem */
	enum {
		STATE_NOTHING,
		STATE_INIT,
		STATE_OPEN,
		STATE_CLAIMED,
		STATE_CONFIGURED
	} state;

	/* buffer for received data */
	unsigned char recv_buf[0x20000];
	int recv_len;
	
	/* sequence number for current send/recv transaction pair */
	unsigned short seq;

	/* The last response from the device, valid immediately after a recv() */
	unsigned char buf[0x40];
	int len;

	/* buffer to hold raw scanlines */
	unsigned char *scanline_buf;
	int scanline_count;
} vfs_dev_t;


enum {
	FP_FRAME_SIZE = 288,
#ifndef OUTPUT_RAW
	FP_LINE_WIDTH = 200,
#else
	FP_LINE_WIDTH = FP_FRAME_SIZE,
#endif

	FP_SUM_LINES = 3,
	/* TODO: The following changes (seen ~60 and ~80) In that 
	 * case we'll need to calibrate this from empty data somehow... */
	FP_SUM_MEDIAN = 60,
	FP_SUM_EMPTY_RANGE = 5,
} fp_line_flag_data;

typedef struct {
	unsigned char sync_0x01;
	unsigned char sync_0xfe;
	
	unsigned char counter_lo;
	unsigned char counter_hi;

	unsigned char sync_0x08[2]; // always? 0x08 0x08
	// 0x08 | 0x18 - Looks like 0x08 marks good quality lines
	unsigned char flag_1;
	unsigned char sync_0x00;
	
	unsigned char scan[200];
	
	/* A offseted, stretched, inverted copy of scan... probably could
	 * serve finger motion speed detection?
	 * Seems to be subdivided to some 10B + 53B + 1B blocks */
	unsigned char mirror[64];
	
	/* Some kind of sum of the scan, very low contrast */
	unsigned char sum1[2];
	unsigned char sum2[11];
	unsigned char sum3[3];
} fp_line_t;

int usb_recv(vfs_dev_t *dev, unsigned char endpoint, int max_bytes);
int usb_send(vfs_dev_t *dev, const unsigned char *data, int length);

void proto_init(vfs_dev_t *dev);
void proto_deinit(vfs_dev_t *dev);
