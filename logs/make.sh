#!/bin/sh

for f in `ls *.csv | grep -v cut | sed s/.csv//`; do
	echo $f
	./process.py $f
done