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
#include "vfs301_proto_fragments.h"
#include <unistd.h>

#define min(a, b) (((a) < (b)) ? (a) : (b))

/************************** OUT MESSAGES GENERATION ***************************/

static void proto_generate_0B(int subtype, unsigned char *data, int *len)
{
	*data = 0x0B;
	*len = 1;
	data++;
	
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
	(((c) >= '0' && (c) <= '9') ? ((c) - '0') : ((c) - 'A' + 10))
	
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
}

static void proto_generate(int type, int subtype, unsigned char *data, int *len)
{
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
		*data = type;
		*len = 1;
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
		case 0x2C01:
		case 0x5E01:
			translate_str(vfs301_next_scan_template, data, len);
			unsigned char *field = data + *len - (sizeof(S4_TAIL) - 1) / 2 - 4;
			
			assert(*field == 0xDE);
			assert(*(field + 1) == 0xAD);
			assert(*(field + 2) == 0xDE);
			assert(*(field + 3) == 0xAD);
			
			*field = (unsigned char)((subtype >> 8) & 0xFF);
			*(field + 1) = (unsigned char)(subtype & 0xFF);
			*(field + 2) = *field;
			*(field + 3) = *(field + 1);
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
	
	for (i = no_lines - VFS301_FP_SUM_LINES; i < no_lines; i++) {
		/* check the line for fingerprint data */
		for (j = 0; j < sizeof(lines[i].sum2); j++) {
			if (lines[i].sum2[j] > (VFS301_FP_SUM_MEDIAN + VFS301_FP_SUM_EMPTY_RANGE))
				rv = 0;
		}
	}
	
	return rv;
}
#endif

#ifdef STORE_SCANS
static int scanline_diff(const unsigned char *scanlines, int prev, int cur)
{
	const unsigned char *line1 = 
		scanlines + prev * VFS301_FP_OUTPUT_WIDTH;
	const unsigned char *line2 = 
		scanlines + cur * VFS301_FP_OUTPUT_WIDTH;
	int i;
	int diff;
	
#ifdef OUTPUT_RAW
	/* We only need the image, not the surrounding stuff. */
	line1 = ((fp_line_t*)line1)->scan;
	line2 = ((fp_line_t*)line2)->scan;
#endif
	
	for (diff = 0, i = 0; i < VFS301_FP_WIDTH; i++) {
		if (*line1 > *line2)
			diff += *line1 - *line2;
		else
			diff += *line2 - *line1;
		
		line1++;
		line2++;
	}
	
	return ((diff / VFS301_FP_WIDTH) > VFS301_FP_LINE_DIFF_THRESHOLD);
}

/** Transform the input data to a normalized fingerprint scan */
static unsigned char *
	scanlines_to_img(const unsigned char *scanlines, int lines, 
	int *output_height
)
{
	int last_line;
	int i;
	unsigned char *output;
	
	assert(lines >= 1);
	
	output = malloc(VFS301_FP_OUTPUT_WIDTH);
	*output_height = 1;
	memcpy(output, scanlines, VFS301_FP_OUTPUT_WIDTH);
	last_line = 0;
	
	/* The following algorithm is quite trivial - it just picks lines that
	 * differ more than VFS301_FP_LINE_DIFF_THRESHOLD.
	 * TODO: A nicer approach would be to pick those lines and then do some kind 
	 * of bi/tri-linear resampling to get the output (so that we don't get so
	 * many false edges etc.).
	 */
	for (i = 1; i < lines; i++) {
		if (scanline_diff(scanlines, last_line, i)) {
			output = realloc(output, VFS301_FP_OUTPUT_WIDTH * (*output_height + 1));
			memcpy(
				output + VFS301_FP_OUTPUT_WIDTH * (*output_height),
				scanlines + VFS301_FP_OUTPUT_WIDTH * i,
				VFS301_FP_OUTPUT_WIDTH
			);
			last_line = i;
			(*output_height)++;
		}
	}
	
	return output;
}

static void img_store(vfs301_dev_t *dev)
{
	static int idx = 0;
	char fn[32];
	FILE *f;
	unsigned char *img;
	int height;
	
	img = scanlines_to_img(dev->scanline_buf, dev->scanline_count, &height);
	
	sprintf(fn, "scan_%02d.pgm", idx++);
	
	f = fopen(fn, "wb");
	assert(f != NULL);
	
	fprintf(f, "P5\n%d %d\n255\n", VFS301_FP_OUTPUT_WIDTH, height);
	fwrite(img, height * VFS301_FP_OUTPUT_WIDTH, 1, f);
	fclose(f);
	
	free(img);
}
#endif

static int img_process_data(
	int first_block, vfs301_dev_t *dev, const unsigned char *buf, int len
)
{
	vfs301_line_t *lines = (vfs301_line_t*)buf;
	int no_lines = len / sizeof(vfs301_line_t);
	int i;
	int no_nonempty;
	char *cur_line;
	int last_img_height;
#ifdef SCAN_FINISH_DETECTION
	int finished_scan;
#endif
	
	if (first_block) {
		last_img_height = 0;
		dev->scanline_count = no_lines;
	} else {
		last_img_height = dev->scanline_count;
		dev->scanline_count += no_lines;
	}
	
	dev->scanline_buf = realloc(dev->scanline_buf, dev->scanline_count * VFS301_FP_OUTPUT_WIDTH);
	assert(dev->scanline_buf != NULL);
	
	for (cur_line = dev->scanline_buf + last_img_height * VFS301_FP_OUTPUT_WIDTH, no_nonempty = 0, i = 0; 
		i < no_lines; 
		i++, cur_line += VFS301_FP_OUTPUT_WIDTH
	) {
#ifndef OUTPUT_RAW
		memcpy(cur_line, lines[i].scan, VFS301_FP_OUTPUT_WIDTH);
#else
		memcpy(cur_line, &lines[i], VFS301_FP_OUTPUT_WIDTH);
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

#define IS_VFS301_FP_SEQ_START(b) ((b[0] == 0x01) && (b[1] == 0xfe))

static int proto_process_data(int first_block, vfs301_dev_t *dev)
{
	int i;
	const unsigned char *buf = dev->recv_buf;
	int len = dev->recv_len;
	
	if (first_block) {
		assert(len >= VFS301_FP_FRAME_SIZE);
		
		// Skip bytes until start_sequence is found
		for (i = 0; i < VFS301_FP_FRAME_SIZE; i++, buf++, len--) {
			if (IS_VFS301_FP_SEQ_START(buf))
				break;
		}
	}
	
	return img_process_data(first_block, dev, buf, len);
}

static void proto_wait_for_event(vfs301_dev_t *dev)
{
	const char no_event[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	const char got_event[] = {0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00};
	
	USB_SEND(0x0220, 0xFA00);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2); //000000000000
	
#ifdef DEBUG
	fprintf(stderr, "Entering proto_wait_for_event() loop...\n");
#endif
	
	while (1) {
		USB_SEND(0x17, -1);
		assert(usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 7) == 0);
		
		if (memcmp(dev->recv_buf, no_event, sizeof(no_event)) == 0) {
			usleep(200000);
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

static void proto_process_event(vfs301_dev_t *dev)
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
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_DATA, 64);
	/* now read the fingerprint data, while there are some */
	while (1) {
		to_recv = first_block ? 84032 : 84096;
		
		rv = usb_recv(
			dev, VFS301_RECEIVE_ENDPOINT_DATA, to_recv
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
		usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2), //1204
		usb_recv(dev, VFS301_RECEIVE_ENDPOINT_DATA, 16384)
	);
	
	USB_SEND(0x0220, 2);
	VARIABLE_ORDER(
		usb_recv(dev, VFS301_RECEIVE_ENDPOINT_DATA, 5760), //seems to come always
		usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2) //0000
	);
}

void proto_init(vfs301_dev_t *dev)
{
	USB_SEND(0x01, -1);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 38);
	USB_SEND(0x0B, 0x04);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 6); //000000000000
	USB_SEND(0x0B, 0x05);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 7); //00000000000000
	USB_SEND(0x19, -1);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 64);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 4); //6BB4D0BC
	usb_send(dev, RAW_DATA(vfs301_06_1));
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2); //0000
	
	USB_SEND(0x01, -1);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 38);
	USB_SEND(0x1A, -1);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_send(dev, RAW_DATA(vfs301_06_2));
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2); //0000
	USB_SEND(0x0220, 1);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_DATA, 256);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_DATA, 32);
	
	USB_SEND(0x1A, -1);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_send(dev, RAW_DATA(vfs301_06_3));
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2); //0000
	
	USB_SEND(0x01, -1);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 38);
	USB_SEND(0x02D0, 1);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_DATA, 11648);
	USB_SEND(0x02D0, 2);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_DATA, 53248);
	USB_SEND(0x02D0, 3);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_DATA, 19968);
	USB_SEND(0x02D0, 4);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_DATA, 5824);
	USB_SEND(0x02D0, 5);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_DATA, 6656);
	USB_SEND(0x02D0, 6);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_DATA, 6656);
	USB_SEND(0x02D0, 7);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_DATA, 832);
	usb_send(dev, RAW_DATA(vfs301_12));
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2); //0000
	
	USB_SEND(0x1A, -1);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_send(dev, RAW_DATA(vfs301_06_2));
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2); //0000
	USB_SEND(0x0220, 2);
	VARIABLE_ORDER(
		usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2), //0000
		usb_recv(dev, VFS301_RECEIVE_ENDPOINT_DATA, 5760)
	);
	
	USB_SEND(0x1A, -1);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_send(dev, RAW_DATA(vfs301_06_1));
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2); //0000
	
	USB_SEND(0x1A, -1);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_send(dev, RAW_DATA(vfs301_06_4));
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2); //0000
	usb_send(dev, RAW_DATA(vfs301_24)); /* turns on white */
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2); //0000
	
	USB_SEND(0x01, -1);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 38);
	USB_SEND(0x0220, 3);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 2368);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_CTRL, 36);
	usb_recv(dev, VFS301_RECEIVE_ENDPOINT_DATA, 5760);
	
	while (1) {
		fprintf(stderr, "waiting for next fingerprint...\n");
		proto_wait_for_event(dev);
		fprintf(stderr, "reading fingerprint...\n");
		proto_process_event(dev);
	}
}

void proto_deinit(vfs301_dev_t *dev)
{
}
