#!/usr/bin/env python

import re
import sys
import os
import csv
import binascii

def hexify(s):
	rv = "\t"
	l = 0
	
	while len(s) > 0:
		rv += "0x%s, " % (s[0:2])
		s = s[2:]
		l += 1
		if (l == 8):
			rv += "\n\t"
			l = 0
	return rv

def parseCsv(path):
	csv.field_size_limit(1000000)
	f = open(path, 'rd')
	cr = csv.reader(f, delimiter=',')

	lines=[]
	for l in cr:
		if len(l) < 16:
			continue
		
		if (l[12] != "usbhub"):
			continue
		
		lines += [[l[1], l[3], l[6], l[8], l[9], l[14], l[15].replace(' ', '')]]
	
	return lines
	
def dumpCutCsv(path, lines):
	w = csv.writer(open(path, 'w')).writerows(lines)

def dumpPgm(path, lines):
	LINEWIDTH = 288
	#LINEWIDTH = 208
	
	raw = ""
	for l in lines:
		#if l[3] == "in" and l[4] == "01:00:82":
			raw += l[6]
			
			raw += "FFEFDFCFBFAF"
			raw += "00" * (LINEWIDTH - (len(l[6])/2 % LINEWIDTH) - 6)
			raw += "0055005500550055" + "00" * (LINEWIDTH - 8)
			raw += "00" * LINEWIDTH
			raw += "FF" * LINEWIDTH

	rf = open(path, 'w')

	height = len(raw) / 2 / LINEWIDTH

	rf.write("P5\n%d %d\n255\n" % (LINEWIDTH, height))
	rf.write(binascii.unhexlify(raw))

def dumpSrc(pathc, pathh, lines):
	usedCmdCodes = [0] * 256
	usedBlocks = []
	
	rc = open(pathc, 'w')
	rh = open(pathh, 'w')

	noBytes = re.compile("([0-9]*) bytes? data")
	portId = re.compile("01:00:(..)")

	lastNameIdx = 0
	
	for l in lines:
		if l[4] == "--:--:00":
			continue
		
		nb = int(noBytes.match(l[2]).group(1))
		
		if l[3] == "in":
			if portId.match(l[4]).group(1) == "81":
				port = "VALIDITY_RECEIVE_ENDPOINT_CTRL"
			else:
				port = "VALIDITY_RECEIVE_ENDPOINT_DATA"
			
			if (nb <= 7):
				comment = " //%s" % l[6]
			else:
				comment = ""
			
			rc.write("usb_recv(dev, %s, %d);%s\n" % (port, nb, comment))
		else:
			newType = 1
			
			dataHexified = hexify(l[6])
			
			if nb == 1:
				name = "vfs301_cmd_%s" % (l[6])
				
				i = int(l[6], 16)
				
				if (not usedCmdCodes[i]):
					usedCmdCodes[i] = 1
				else:
					newType = 0
			else:
				try:
					idx = usedBlocks.index(dataHexified)
					newType = 0
				except:
					usedBlocks += [dataHexified]
					idx = lastNameIdx
					lastNameIdx += 1
				
				name = "vfs301_init_%02d" % (idx)

			if (newType):
				rh.write("static const char %s[] = { /* %d B */\n%s\n};\n\n" % (name, nb, dataHexified))
			rc.write("usb_send(dev, B(%s));\n" % (name))
			
lines = parseCsv(sys.argv[1] + ".csv")

dumpCutCsv(sys.argv[1] + "-cut.csv", lines)
dumpPgm(sys.argv[1] + ".pgm", lines)
dumpSrc(sys.argv[1] + ".c", sys.argv[1] + ".h", lines)
