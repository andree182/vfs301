#!/bin/sh

python - $1 <<.

import sys
s = sys.argv[1]
l = 1

print("")

while len(s) > 0:
	sys.stdout.write("0x%s, " % (s[0:2]))
	if (l == 8):
		print("")
		l = 0
	s = s[2:]
	l += 1

print("");
.