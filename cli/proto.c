/*
 * vfs301 fingerprint driver 
 * 
 * Copyright (c) 2011 Andrej Krutak <andree@andree.sk>
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

#include "proto.h"
#include <unistd.h>

#define DEBUG
#define OUTPUT_RAW
#define STORE_SCANS

#define min(a, b) (((a) < (b)) ? (a) : (b))

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

	/* buffer to hold raw image data frames */
	unsigned char *img_buf;
	int img_height;
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

/************************** USB STUFF *****************************************/

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

	dev->devh = libusb_open_device_with_vid_pid(NULL, 0x138a, 0x0005);
	if (dev->devh == NULL) {
		fprintf(stderr, "Can't open validity device!\n");
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
	fprintf(stderr, "%s, rv %d, len %d\n", dir ? "send" : "recv", rv, length);

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


static int usb_recv(vfs_dev_t *dev, unsigned char endpoint, int max_bytes)
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

static int usb_send(vfs_dev_t *dev, const unsigned char *data, int length)
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

/************************** SCAN IMAGE STUFF **********************************/

#ifdef SCAN_FINISH_DETECTION
static int img_is_finished_scan(fp_line_t *lines, int no_lines)
{
	int i;
	int j;
	int rv = 1;
	
	for (i = no_lines - FP_SUM_LINES; i < no_lines; i++) {
		/* check the line for fingerprint data */
		for (j = 0; j < sizeof(lines[i].sum2); j++) {
			if (lines[i].sum2[j] > (FP_SUM_MEDIAN + FP_SUM_EMPTY_RANGE))
				rv = 0;
		}
	}
	
	return rv;
}
#endif

#ifdef STORE_SCANS
static void img_store(vfs_dev_t *dev)
{
	static int idx = 0;
	char fn[32];
	FILE *f;
	
	sprintf(fn, "scan_%02d.pgm", idx++);
	
	f = fopen(fn, "wb");
	assert(f != NULL);
	
	fprintf(f, "P5\n%d %d\n255\n", FP_LINE_WIDTH, dev->img_height);
	fwrite(dev->img_buf, dev->img_height * FP_LINE_WIDTH, 1, f);
	fclose(f);
}
#endif

static int img_process_data(
	int first_block, vfs_dev_t *dev, const unsigned char *buf, int len
)
{
	fp_line_t *lines = (fp_line_t*)buf;
	int no_lines = len / sizeof(fp_line_t);
	int i;
	int no_nonempty;
	char *cur_line;
	int last_img_height;
#ifdef SCAN_FINISH_DETECTION
	int finished_scan;
#endif
	
	if (first_block) {
		last_img_height = 0;
		dev->img_height = no_lines;
	} else {
		last_img_height = dev->img_height;
		dev->img_height += no_lines;
	}
	
	dev->img_buf = realloc(dev->img_buf, dev->img_height * FP_LINE_WIDTH);
	assert(dev->img_buf != NULL);
	
	for (cur_line = dev->img_buf + last_img_height * FP_LINE_WIDTH, no_nonempty = 0, i = 0; 
		i < no_lines; 
		i++, cur_line += FP_LINE_WIDTH
	) {
#ifndef OUTPUT_RAW
		memcpy(cur_line, lines[i].scan, FP_LINE_WIDTH);
#else
		memcpy(cur_line, &lines[i], FP_LINE_WIDTH);
#endif
	}
	
#ifdef SCAN_FINISH_DETECTION
	finished_scan = img_is_finished_scan(lines, no_lines);
	
#ifdef STORE_SCANS
	if (finished_scan) {
		img_store(dev);
	}
#endif

	return !finished_scan;
#else /* SCAN_FINISH_DETECTION */
	return 1; //Just continue until data are coming
#endif
}

/************************** PROTOCOL STUFF ************************************/

#define B(x) x, sizeof(x)

#define IS_FP_SEQ_START(b) ((b[0] == 0x01) && (b[1] == 0xfe))

static int proto_process_data(int first_block, vfs_dev_t *dev)
{
	int i;
	const unsigned char *buf = dev->recv_buf;
	int len = dev->recv_len;
	
	if (first_block) {
		assert(len >= FP_FRAME_SIZE);
		
		// Skip bytes until start_sequence is found
		for (i = 0; i < FP_FRAME_SIZE; i++, buf++, len--) {
			if (IS_FP_SEQ_START(buf))
				break;
		}
	}
	
	return img_process_data(first_block, dev, buf, len);
}

static void proto_wait_for_event(vfs_dev_t *dev)
{
	const char no_event[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	const char got_event[] = {0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00};
	
#ifdef DEBUG
	fprintf(stderr, "Entering proto_wait_for_event() loop...\n");
#endif
	
	while (1) {
		usb_send(dev, B(vfs301_cmd_17));
		assert(usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 7) == 0);
		
		if (memcmp(dev->recv_buf, no_event, sizeof(no_event)) == 0) {
			usleep(60000);
		} else if (memcmp(dev->recv_buf, got_event, sizeof(no_event)) == 0) {
			break;
		} else {
			assert(!"unexpected reply to wait");
		}
	}
}

#define VARIABLE_ORDER(a, b) \
	{ \
		int rv = a;\
		b; \
		if (rv == -7) \
			a; \
	}

static void proto_process_event(vfs_dev_t *dev)
{
	int first_block = 1;
	int rv;
	int to_recv;
	
	/* 
	 * Notes:
	 * 
	 * seen next_scan order:
	 *    o FA00
	 *    o FA00
	 *    o 2C01
	 *    o FA00
	 *    o FA00
	 *    o 2C01
	 *    o FA00
	 *    o FA00
	 *    o 2C01
	 *    o 5E01 !?
	 *    o FA00
	 *    o FA00
	 *    o 2C01
	 *    o FA00
	 *    o FA00
	 *    o 2C01
	 */
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 64);
	/* now read the fingerprint data, while there are some */
	while (1) {
		to_recv = first_block ? 84032 : 84096;
		
		rv = usb_recv(
			dev, VALIDITY_RECEIVE_ENDPOINT_DATA, to_recv
		);
		
		if (rv == LIBUSB_ERROR_TIMEOUT)
			break;
		assert(rv == 0);
		if (dev->recv_len < to_recv)
			break;
		
		if (!proto_process_data(first_block, dev))
			break;
		
		first_block = 0;
	}
	
#ifndef SCAN_FINISH_DETECTION
#ifdef STORE_SCANS
	img_store(dev);
#endif
#endif

	usb_send(dev, B(vfs301_cmd_04));
	/* the following may come in random order, data may not come at all, don't
	 * try for too long... */
	VARIABLE_ORDER(
		usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2), //1204
		usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 16384)
	);
	
	usb_send(dev, B(vfs301_init_14));
	VARIABLE_ORDER(
		usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 5760), //seems to come always
		usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2) //0000
	);
	usb_send(dev, B(vfs301_next_scan_FA00));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
}

static void proto_init(vfs_dev_t *dev)
{
	usb_send(dev, B(vfs301_cmd_01));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 38);
	usb_send(dev, B(vfs301_init_00));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 6); //000000000000
	usb_send(dev, B(vfs301_init_01));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 7); //00000000000000
	usb_send(dev, B(vfs301_cmd_19));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 64);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 4); //6BB4D0BC
	usb_send(dev, B(vfs301_init_02));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	
	usb_send(dev, B(vfs301_cmd_01));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 38);
	usb_send(dev, B(vfs301_cmd_1A));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_send(dev, B(vfs301_init_03));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_send(dev, B(vfs301_init_04));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 256);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 32);
	
	usb_send(dev, B(vfs301_cmd_1A));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_send(dev, B(vfs301_init_05));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	
	usb_send(dev, B(vfs301_cmd_01));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 38);
	usb_send(dev, B(vfs301_init_06));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 11648);
	usb_send(dev, B(vfs301_init_07));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 53248);
	usb_send(dev, B(vfs301_init_08));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 19968);
	usb_send(dev, B(vfs301_init_09));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 5824);
	usb_send(dev, B(vfs301_init_10));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 6656);
	usb_send(dev, B(vfs301_init_11));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 6656);
	usb_send(dev, B(vfs301_init_12));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 832);
	usb_send(dev, B(vfs301_init_13));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	
	usb_send(dev, B(vfs301_cmd_1A));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_send(dev, B(vfs301_init_03));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_send(dev, B(vfs301_init_14));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 5760);
	
	usb_send(dev, B(vfs301_cmd_1A));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_send(dev, B(vfs301_init_02));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	
	/* turns on white */
	usb_send(dev, B(vfs301_cmd_1A));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_send(dev, B(vfs301_init_15));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_send(dev, B(vfs301_init_16));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
// 	fprintf(stderr, "-------------- turned on white \n"); sleep(1);
	
	usb_send(dev, B(vfs301_cmd_01));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 38);
	usb_send(dev, B(vfs301_init_17));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2368);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 36);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 5760);
	usb_send(dev, B(vfs301_next_scan_FA00));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
// 	fprintf(stderr, "-------------- turned off white\n"); sleep(1);
	
	fprintf(stderr, "-------------- waiting for fingerprint ------------\n");
	
	while (1) {
		proto_wait_for_event(dev);
		proto_process_event(dev);
	}
}

static void proto_deinit(vfs_dev_t *dev)
{
}


/************************** GENERIC STUFF *************************************/


static vfs_dev_t dev;

static void init(vfs_dev_t *dev)
{
	dev->state = STATE_NOTHING;
	dev->img_buf = malloc(0);
	dev->img_height = 0;
	
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
	
	free(dev->img_buf);
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
