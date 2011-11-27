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

#include "proto.h"
#include "proto_fragments.h"
#include <unistd.h>

#define DEBUG
#define OUTPUT_RAW
#define STORE_SCANS

#define min(a, b) (((a) < (b)) ? (a) : (b))

/************************** OUT MESSAGES GENERATION ***************************/

static void proto_generate_0B(int subtype, unsigned char *data, int *len)
{
	memset(data, 0, 39);
	*len += 38;
	
	data[20] = subtype;
	
	switch (subtype) {
	case 0x04:
		data[34] = 0x9F;
		break;
	case 0x05:
		data[34] = 0xAB;
		len++;
		break;
	default:
		assert(!"unsupported");
		break;
	}
}

#define HEX_TO_INT(c) \
	(((c) >= '0' && (c) <= '9') ? ((c) - '0') : ((c) - 'A'))
	
static void translate_str(const char **srcL, unsigned char *data, int *len)
{
	const char *src;
	unsigned char *dataOrig = data;
	
	while (*srcL != NULL) {
		src = *srcL;
		while (*src != '\0') {
			assert(*src != '\0');
			assert(*(src +1) != '\0');
			*data = 
				(unsigned char)((HEX_TO_INT(*src) << 4) | (HEX_TO_INT(*(src + 1))));

			data++;
			src += 2;
		}
		
		srcL++;
	}
	
	*len = data - dataOrig;
	
// 	fprintf(stderr, "CALCLEN %d\n", *len);
}

static void proto_generate(int type, int subtype, unsigned char *data, int *len)
{
	*data = type;
	*len = 1;
	data++;
		
	switch (type) {
	case 0x01:
	case 0x04:
		/* After cmd 0x04 is sent, a data is received on VALIDITY_RECEIVE_ENDPOINT_CTRL.
		 * If it is 0x0000:
		 *     additional 64B and 224B are read from _DATA, then vfs301_next_scan_FA00 is
		 *     sent, 0000 received from _CTRL, and then continue with wait loop
		 * If it is 0x1204:
		 *     => reinit?
		 */
	case 0x17:
	case 0x19:
	case 0x1A:
		break;
	case 0x0B:
		proto_generate_0B(subtype, data, len);
		break;
	case 0x02D0:
		{
			const char **dataLs[] = {
				vfs301_02D0_01, 
				vfs301_02D0_02, 
				vfs301_02D0_03, 
				vfs301_02D0_04, 
				vfs301_02D0_05, 
				vfs301_02D0_06, 
				vfs301_02D0_07, 
			};
			assert((int)subtype <= (int)(sizeof(dataLs) / sizeof(dataLs[0])));
			translate_str(dataLs[subtype - 1], data, len);
		}
		break;
	case 0x0220:
		switch (subtype) {
		case 1:
			translate_str(vfs301_0220_01, data, len);
			break;
		case 2:
			translate_str(vfs301_0220_02, data, len);
			break;
		case 3:
			translate_str(vfs301_0220_03, data, len);
			break;
		case 0xFA00:
			translate_str(vfs301_next_scan_FA00, data, len);
			break;
		case 0x2C01:
			translate_str(vfs301_next_scan_2C01, data, len);
			break;
		case 0x5E01:
			translate_str(vfs301_next_scan_5E01, data, len);
			break;
		default:
			assert(0);
			break;
		}
		break;
	case 0x06:
		assert(!"Not generated");
		break;
	default:
		assert(!"Unknown message type");
		break;
	}
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
	return 1; //Just continue until data is coming
#endif
}

/************************** PROTOCOL STUFF ************************************/

static unsigned char usb_send_buf[0x2000];

#define USB_SEND(type, subtype) \
	{ \
		int len; \
		proto_generate(type, subtype, usb_send_buf, &len); \
		usb_send(dev, usb_send_buf, len); \
	}

#define RAW_DATA(x) x, sizeof(x)

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
		USB_SEND(0x17, -1);
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

	USB_SEND(0x04, -1);
	/* the following may come in random order, data may not come at all, don't
	 * try for too long... */
	VARIABLE_ORDER(
		usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2), //1204
		usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 16384)
	);
	
	USB_SEND(0x0220, 2);
	VARIABLE_ORDER(
		usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 5760), //seems to come always
		usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2) //0000
	);
	USB_SEND(0x0220, 0xFA00);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
}

void proto_init(vfs_dev_t *dev)
{
	USB_SEND(0x01, -1);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 38);
	USB_SEND(0x0B, 0x04);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 6); //000000000000
	USB_SEND(0x0B, 0x05);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 7); //00000000000000
	USB_SEND(0x19, -1);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 64);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 4); //6BB4D0BC
	usb_send(dev, RAW_DATA(vfs301_06_1));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	
	USB_SEND(0x01, -1);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 38);
	USB_SEND(0x1A, -1);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_send(dev, RAW_DATA(vfs301_06_2));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	USB_SEND(0x0220, 1);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 256);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 32);
	
	USB_SEND(0x1A, -1);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_send(dev, RAW_DATA(vfs301_06_3));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	
	USB_SEND(0x01, -1);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 38);
	USB_SEND(0x02D0, 1);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 11648);
	USB_SEND(0x02D0, 2);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 53248);
	USB_SEND(0x02D0, 3);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 19968);
	USB_SEND(0x02D0, 4);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 5824);
	USB_SEND(0x02D0, 5);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 6656);
	USB_SEND(0x02D0, 6);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 6656);
	USB_SEND(0x02D0, 7);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 832);
	usb_send(dev, RAW_DATA(vfs301_12));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	
	USB_SEND(0x1A, -1);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_send(dev, RAW_DATA(vfs301_06_2));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	USB_SEND(0x0220, 2);
	VARIABLE_ORDER(
		usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2), //0000
		usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 5760)
	);
	
	USB_SEND(0x1A, -1);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_send(dev, RAW_DATA(vfs301_06_1));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	
	USB_SEND(0x1A, -1);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_send(dev, RAW_DATA(vfs301_06_4));
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_send(dev, RAW_DATA(vfs301_24)); /* turns on white */
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
// 	fprintf(stderr, "-------------- turned on white \n"); sleep(1);
	
	USB_SEND(0x01, -1);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 38);
	USB_SEND(0x0220, 3);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2368);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 36);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_DATA, 5760);
	USB_SEND(0x0220, 0xFA00);
	usb_recv(dev, VALIDITY_RECEIVE_ENDPOINT_CTRL, 2); //0000
// 	fprintf(stderr, "-------------- turned off white\n"); sleep(1);
	
	fprintf(stderr, "-------------- waiting for fingerprint ------------\n");
	
	while (1) {
		proto_wait_for_event(dev);
		proto_process_event(dev);
	}
}

void proto_deinit(vfs_dev_t *dev)
{
}
